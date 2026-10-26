"""Reading the text of mail that an SES archive holds: finding the message, turning it into safe text, who may open it."""
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from django.urls import reverse
from django.utils import timezone as djtz

from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata import archive, setupcheck
from apps.sesdata.ingest import process_body
from apps.sesdata.models import BodyAccessLog, Message

from . import factories as f
from .test_views import login

pytestmark = pytest.mark.django_db
TOPICS = [f.TOPIC]
ARCHIVE = "a-test1234"
SENT = datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parent.parent
REGION = "ap-south-1"


def row(mid, **kw):
    return {"ArchivedMessageId": f"0c/{ARCHIVE}/{mid}/{mid}", "MessageId": f"<{mid}@{REGION}.amazonses.com>", "From": "Acme <cloud@example.com>",
            "To": "alice@example.com", "Cc": "", "Subject": "Your invoice", "Date": "x", **kw}


class FakeMM:
    """A stand-in for the Mail Manager client. `rows` per search; `states` are the answers while it polls."""

    def __init__(self, rows=None, content=None, states=("COMPLETED",), error=None, second=None):
        self.rows, self.content_body, self.states, self.error, self.second = rows or [], content, list(states), error, second
        self.calls, self.polls = [], 0

    def _boom(self):
        if self.error:
            raise self.error

    def start_archive_search(self, **kw):
        self._boom()
        self.calls.append(("start", kw))
        return {"SearchId": f"s{len([c for c in self.calls if c[0] == 'start'])}"}

    def get_archive_search(self, SearchId):
        self.polls += 1
        return {"Status": {"State": self.states[min(self.polls - 1, len(self.states) - 1)]}}

    def get_archive_search_results(self, SearchId):
        self.calls.append(("results", SearchId))
        return {"Rows": self.second if (SearchId == "s2" and self.second is not None) else self.rows}

    def get_archive_message_content(self, ArchivedMessageId):
        self._boom()
        self.calls.append(("content", ArchivedMessageId))
        return {"Body": self.content_body if self.content_body is not None else {"Text": "Hello Alice.\nYour invoice is ready."}}

    state = "ACTIVE"

    def get_archive(self, ArchiveId):
        self._boom()
        return {"ArchiveState": self.state, "Retention": {"RetentionPeriod": "THREE_MONTHS"}}

    def starts(self):
        return [c[1] for c in self.calls if c[0] == "start"]


def reader(mm, **kw):
    return archive.Reader(mm=mm, archive_id=ARCHIVE, sleep=lambda s: None, **kw)


def aws_error(code="AccessDenied"):
    return ClientError({"Error": {"Code": code, "Message": "secret AWS detail"}}, "StartArchiveSearch")


# ---------------------------------------------------------------- finding the message
def test_the_message_is_found_by_its_message_id_header_in_a_window_around_the_send():
    mm = FakeMM(rows=[row("other-1"), row("abc123"), row("other-2")])
    found = reader(mm).find("abc123", SENT)
    assert found["ArchivedMessageId"].endswith("abc123/abc123")
    (kw,) = mm.starts()
    assert kw["ArchiveId"] == ARCHIVE and kw["FromTimestamp"] == SENT - timedelta(minutes=5) and kw["ToTimestamp"] == SENT + timedelta(minutes=30)
    assert kw["MaxResults"] == archive.MAX_RESULTS and "Filters" not in kw


def test_an_id_that_is_only_the_start_of_another_id_is_not_a_match():
    with pytest.raises(archive.NotArchived):
        reader(FakeMM(rows=[row("abc1234"), row("xabc123")])).find("abc123", SENT)


def test_a_message_that_is_not_in_the_archive_says_so_in_plain_words():
    with pytest.raises(archive.NotArchived) as e:
        reader(FakeMM(rows=[row("other")])).find("abc123", SENT)
    assert "No archived copy" in str(e.value) and "secret" not in str(e.value)


def test_a_full_page_of_other_mail_triggers_one_narrower_search_for_that_recipient():
    busy = [row(f"x{i}") for i in range(archive.MAX_RESULTS)]
    mm = FakeMM(rows=busy, second=[row("abc123")])
    assert reader(mm).find("abc123", SENT, "alice@example.com")["MessageId"].startswith("<abc123@")
    first, second = mm.starts()
    assert "Filters" not in first
    assert second["Filters"]["Include"][0]["StringExpression"] == {"Evaluate": {"Attribute": "ENVELOPE_TO"}, "Operator": "CONTAINS", "Values": ["alice@example.com"]}


def test_no_narrower_search_when_the_first_one_was_not_full_or_there_is_no_recipient():
    mm = FakeMM(rows=[row("x")])
    with pytest.raises(archive.NotArchived):
        reader(mm).find("abc123", SENT, "alice@example.com")
    assert len(mm.starts()) == 1
    mm = FakeMM(rows=[row(f"x{i}") for i in range(archive.MAX_RESULTS)])
    with pytest.raises(archive.NotArchived):
        reader(mm).find("abc123", SENT, None)
    assert len(mm.starts()) == 1


@pytest.mark.parametrize("bad", ["", "a b", "a/b", "../x", "a" * 201, "id<script>"])
def test_an_unusable_message_id_is_refused_before_anything_is_asked_of_aws(bad):
    mm = FakeMM()
    with pytest.raises(archive.NotArchived):
        reader(mm).find(bad, SENT)
    assert mm.calls == []


def test_the_search_is_polled_until_it_completes():
    mm = FakeMM(rows=[row("abc123")], states=("QUEUED", "RUNNING", "COMPLETED"))
    reader(mm).find("abc123", SENT)
    assert mm.polls == 3


def test_a_search_that_never_finishes_gives_up_with_a_plain_message():
    mm = FakeMM(rows=[row("abc123")], states=("RUNNING",))
    with pytest.raises(archive.ArchiveError) as e:
        reader(mm, timeout=6).find("abc123", SENT)
    assert "took too long" in str(e.value) and not isinstance(e.value, archive.NotArchived)
    assert mm.polls <= 5


@pytest.mark.parametrize("state", ["FAILED", "CANCELLED"])
def test_a_failed_search_is_reported_not_treated_as_not_found(state):
    mm = FakeMM(states=(state,))
    with pytest.raises(archive.ArchiveError) as e:
        reader(mm).find("abc123", SENT)
    assert not isinstance(e.value, archive.NotArchived) and "could not be searched" in str(e.value) and mm.polls == 1       # stops at once, does not wait out the timeout


def test_the_content_is_returned_with_missing_parts_as_empty():
    assert reader(FakeMM(content={"Text": "t", "MessageMalformed": True})).content("m") == {"text": "t", "html": "", "malformed": True}
    assert reader(FakeMM(content={"Html": "<p>h</p>"})).content("m") == {"text": "", "html": "<p>h</p>", "malformed": False}


# ---------------------------------------------------------------- making it safe to show
def test_the_plain_text_part_is_used_when_there_is_one():
    text, note = archive.readable({"text": "Plain part", "html": "<p>Html part</p>", "malformed": False})
    assert text == "Plain part" and note == ""


def test_html_only_mail_becomes_readable_text_without_scripts_styles_or_markup():
    html = ("<html><head><title>x</title><style>.a{color:red}</style></head><body><h1>Welcome</h1><p>Hi&nbsp;Ann &amp; Bob</p>"
            "<script>alert('x')</script><ul><li>One</li><li>Two</li></ul><a href=\"https://app.example/go?token=SECRET123456\">Open it</a>"
            "<!-- hidden --><br>Bye</body></html>")
    text, _ = archive.readable({"text": "", "html": html, "malformed": False})
    assert "Welcome" in text and "Hi Ann & Bob" in text and "One\nTwo" in text.replace("\n\n", "\n") and "Open it" in text and "Bye" in text
    for leaked in ("<", ">", "alert", "color:red", "hidden", "SECRET123456", "token="):
        assert leaked not in text, leaked


def test_broken_html_does_not_crash_and_never_comes_back_as_raw_markup():
    text, _ = archive.readable({"text": "", "html": "<div><p>unclosed <b>bold <i>x</div></span></p>", "malformed": False})
    assert "unclosed" in text and "<" not in text


@pytest.mark.parametrize("raw, gone, kept", [
    ("Reset: https://app.example/reset?token=abcdef123456&u=1", "abcdef123456", "https://app.example/reset?[redacted]"),
    ("Open https://app.example/path?x=1&y=2 now", "x=1", "https://app.example/path?[redacted]"),
    ("Accept https://app.example/invite/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA now", "Zm9vYmFy", "https://app.example/invite/[redacted]"),
    ("Download https://files.example/d/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA now", "Zm9vYmFy", "https://files.example/d/[redacted]"),   # no keyword in the path: only the long-segment rule can catch it
    ("Your verification code is 482913.", "482913", "code is [redacted]"),
    ("see https://app.example/billing/invoices/123 for details", "NOTHING-TO-HIDE", "https://app.example/billing/invoices/123"),
    ("Key AKIAIOSFODNN7EXAMPLE leaked", "AKIAIOSFODNN7EXAMPLE", "[redacted]"),
])
def test_links_tokens_and_codes_are_redacted_but_ordinary_text_is_not(raw, gone, kept):
    out = archive.redact_for_display(raw)
    assert gone not in out and kept in out


def test_a_malformed_message_and_a_very_long_one_come_with_a_note():
    _, note = archive.readable({"text": "x", "html": "", "malformed": True})
    assert "malformed" in note
    text, note = archive.readable({"text": "a b " * 100_000, "html": "", "malformed": False})
    assert len(text) <= archive.MAX_TEXT and "cut after" in note


# ---------------------------------------------------------------- the console: who can open it, and what is recorded
@pytest.fixture
def arch(settings, monkeypatch):
    settings.MAIL_ARCHIVE_ID, settings.ARCHIVE_VIEW_DAYS = ARCHIVE, 30
    mm = FakeMM(rows=[row("0100app-1")], content={"Text": "Hello Alice\nReset: https://x.example/r?token=SECRETTOKEN99"})
    monkeypatch.setattr(archive, "client", lambda: mm)
    monkeypatch.setattr(archive.time, "sleep", lambda s: None)
    return mm


def app_message(mid="0100app-1", age=timedelta(minutes=10)):
    process_body(f.sns(f.send(mid=mid, ts=(djtz.now() - age).strftime("%Y-%m-%dT%H:%M:%S.000Z"))), TOPICS)
    return Message.objects.get(ses_message_id=mid)


def open_text(client, msg, reason="customer asked"):
    return client.post(reverse("sent_body", args=[msg.pk]), {"reason": reason})


def test_an_admin_reads_archived_mail_with_links_redacted_and_the_view_is_audited(arch):
    c, u = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    msg = app_message()
    r = open_text(c, msg)
    html = r.content.decode()
    assert r.status_code == 200 and "Hello Alice" in html and "SECRETTOKEN99" not in html and "token=" not in html and "[redacted]" in html
    assert "Acme &lt;cloud@example.com&gt;" in html and "alice@example.com" in html and "read from the mail archive" in html
    (log,) = BodyAccessLog.objects.all()
    assert (log.user_email, log.message_id, log.reason) == (u.email, msg.pk, "customer asked")
    (a,) = AuditLog.objects.filter(action="sent_body.view")
    assert a.details["source"] == "archive" and a.details["reason"] == "customer asked" and "Hello" not in str(a.details)


def test_a_get_only_asks_for_the_reason_and_does_not_touch_the_archive(arch):
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    msg = app_message()
    r = c.get(reverse("sent_body", args=[msg.pk]))
    assert r.status_code == 200 and "copy is held in the mail archive" in r.content.decode() and arch.calls == [] and not BodyAccessLog.objects.exists()


def test_the_body_tab_offers_archived_text_to_admins_and_explains_to_others(arch):
    msg = app_message()
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    html = c.get(reverse("message_detail", args=[msg.pk])).content.decode()
    assert reverse("sent_body", args=[msg.pk]) in html and "30 days" in html and "held in the mail archive" in html
    v, _ = login(VIEWER, "v@example.com")
    html = v.get(reverse("message_detail", args=[msg.pk])).content.decode()
    assert reverse("sent_body", args=[msg.pk]) not in html and "Only deliverability and security admins can open it." in html


@pytest.mark.parametrize("role", [VIEWER, SUPPORT])
def test_viewers_and_support_cannot_open_archived_text_and_aws_is_not_asked(arch, role):
    msg = app_message()
    c, _ = login(role, f"{role}@example.com", step_up=True)
    assert open_text(c, msg).status_code == 403 and c.get(reverse("sent_body", args=[msg.pk])).status_code == 403
    assert arch.calls == [] and not BodyAccessLog.objects.exists()


def test_a_passkey_check_comes_first_and_a_reason_is_required(arch):
    msg = app_message()
    c, _ = login(DELIVERABILITY_ADMIN, "nostep@example.com", step_up=False)
    r = open_text(c, msg)
    assert r.status_code == 302 and reverse("step_up") in r["Location"] and arch.calls == []
    c2, _ = login(DELIVERABILITY_ADMIN, "step@example.com", step_up=True)
    assert open_text(c2, msg, reason="  ").status_code == 400 and arch.calls == []


def test_a_person_limited_to_other_domains_gets_a_404_and_aws_is_not_asked(arch):
    msg = app_message()
    c, _ = login(DELIVERABILITY_ADMIN, "scoped@example.com", step_up=True, scope_domains=["other.example"])
    assert open_text(c, msg).status_code == 404 and c.get(reverse("sent_body", args=[msg.pk])).status_code == 404 and arch.calls == []


def test_mail_older_than_the_viewing_window_is_not_opened_and_aws_is_not_asked(arch):
    msg = app_message(age=timedelta(days=31))
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert open_text(c, msg).status_code == 400 and arch.calls == []
    html = c.get(reverse("message_detail", args=[msg.pk])).content.decode()
    assert "older than the console shows" in html and reverse("sent_body", args=[msg.pk]) not in html


def test_the_window_edge_is_the_configured_number_of_days(arch, settings):
    settings.ARCHIVE_VIEW_DAYS = 2
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert open_text(c, app_message("0100app-1", age=timedelta(days=1, hours=23))).status_code == 200
    assert open_text(c, app_message("0100app-2", age=timedelta(days=2, hours=1))).status_code == 400


def test_a_message_the_archive_does_not_hold_shows_a_plain_reason_and_records_nothing_as_read(arch):
    arch.rows = [row("some-other-message")]
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    msg = app_message()
    r = open_text(c, msg)
    html = r.content.decode()
    assert r.status_code == 200 and "No archived copy of this message was found" in html and "Hello Alice" not in html
    assert not BodyAccessLog.objects.exists() and AuditLog.objects.filter(action="sent_body.unavailable").exists()


def test_an_aws_failure_is_reported_in_plain_words_without_aws_text(arch):
    arch.error = aws_error("AccessDenied")
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    r = open_text(c, app_message())
    html = r.content.decode()
    assert r.status_code == 200 and "could not be read right now" in html and "secret AWS detail" not in html and "AccessDenied" not in html
    assert not BodyAccessLog.objects.exists()
    (a,) = AuditLog.objects.filter(action="sent_body.unavailable")
    assert "secret" not in str(a.details)


def test_without_an_archive_the_old_explanation_stays_and_nothing_can_be_opened(settings):
    settings.MAIL_ARCHIVE_ID = ""
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    msg = app_message()
    assert "No body stored for this message" in c.get(reverse("message_detail", args=[msg.pk])).content.decode()
    assert open_text(c, msg).status_code == 400


def test_compose_text_takes_precedence_and_blanked_compose_text_falls_back_to_the_archive(arch):
    from apps.compose.models import SentMail
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    msg = app_message("0100compose-1")
    SentMail.objects.create(user_email="a@x.com", from_address="n@x.com", to_addrs=["alice@example.com"], subject="Hi", recipient_count=1,
                            ses_message_id="0100compose-1", body="Written in Compose")
    html = open_text(c, msg).content.decode()
    assert "Written in Compose" in html and arch.calls == []
    SentMail.objects.update(body="")
    arch.rows = [row("0100compose-1")]
    html = open_text(c, msg).content.decode()
    assert "Hello Alice" in html and arch.calls


def test_the_text_is_shown_escaped_never_rendered(arch):
    arch.content_body = {"Text": "<script>alert(1)</script> & <b>bold</b>"}
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    html = open_text(c, app_message()).content.decode()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "<b>bold</b>" not in html


# ---------------------------------------------------------------- setup check and configuration
def test_the_setup_check_reports_an_active_archive_and_how_long_aws_keeps_it(settings):
    settings.MAIL_ARCHIVE_ID = ARCHIVE
    (c,) = setupcheck._archive_checks(FakeMM())
    assert c.status == "ok" and "three months" in c.detail and "30 days" in c.detail


@pytest.mark.parametrize("state", ["PENDING_DELETION", "", "PAUSED"])
def test_the_setup_check_warns_when_the_archive_is_not_active(settings, state):
    settings.MAIL_ARCHIVE_ID = ARCHIVE
    mm = FakeMM()
    mm.state = state
    (c,) = setupcheck._archive_checks(mm)
    assert c.status == "warn" and "not active" in c.title


def test_the_setup_check_reports_an_unreadable_archive_without_leaking_the_error(settings):
    settings.MAIL_ARCHIVE_ID = ARCHIVE
    (c,) = setupcheck._archive_checks(FakeMM(error=aws_error("AccessDenied")))
    assert c.status == "fail" and "AccessDenied" in c.detail and "secret AWS detail" not in c.detail and "archive-read.json" in c.fix


def test_the_archive_group_appears_only_when_an_archive_is_configured(settings):
    settings.SQS_EVENTS_QUEUE_URL = "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-events"
    settings.MAIL_ARCHIVE_ID = ""
    assert not [c for c in setupcheck.run_checks(REGION) if c.group == "Mail archive"]
    settings.MAIL_ARCHIVE_ID = ARCHIVE
    assert [c for c in setupcheck.run_checks(REGION, mailmanager_client=FakeMM()) if c.group == "Mail archive"]


def _config(**env):
    base = {"MC_SECRET_KEY": "x" * 60, "MC_DEBUG": "0", "MC_CONSOLE_HOST": "console.test", "MC_MAILVIEW_HOST": "mailview.test", "MC_DB_PORT": "54329",
            "MC_WEBAUTHN_ORIGIN": "https://console.test"}
    code = "import os; os.environ['DJANGO_SETTINGS_MODULE']='config.settings'; from config import settings; print(settings.MAIL_ARCHIVE_ID, settings.ARCHIVE_VIEW_DAYS)"
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env={**os.environ, **base, **env}, capture_output=True, text=True)


def test_archive_settings_are_validated_at_start_up():
    assert _config(MC_MAIL_ARCHIVE_ID="a-abc123", MC_ARCHIVE_VIEW_DAYS="14").stdout.strip() == "a-abc123 14"
    assert _config().stdout.strip() == "30"
    for bad in ({"MC_MAIL_ARCHIVE_ID": "abc123"}, {"MC_MAIL_ARCHIVE_ID": "a-bad id"}, {"MC_MAIL_ARCHIVE_ID": "a-x/../y"},
                {"MC_ARCHIVE_VIEW_DAYS": "0"}, {"MC_ARCHIVE_VIEW_DAYS": "4000"}):
        proc = _config(**bad)
        assert proc.returncode != 0 and ("MC_MAIL_ARCHIVE_ID" in proc.stderr or "MC_ARCHIVE_VIEW_DAYS" in proc.stderr), bad


def test_html_only_archived_mail_is_shown_as_text_and_link_targets_are_dropped(arch):
    arch.content_body = {"Html": "<p>Hello Alice</p><p>Reset: <a href='https://x.example/r?token=SECRETTOKEN99'>use this link</a></p>"}
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    html = open_text(c, app_message()).content.decode()
    assert "Hello Alice" in html and "use this link" in html and "SECRETTOKEN99" not in html and "x.example/r" not in html


# ---------------------------------------------------------------- mail categories are followed when they have been set up
def categorised(arch, name="billing", **kw):
    from apps.sesdata.models import MailCategory
    MailCategory.objects.create(name=name, **kw)
    msg = app_message()
    Message.objects.filter(pk=msg.pk).update(mail_category=name)
    return Message.objects.get(pk=msg.pk)


def test_a_category_with_reading_switched_off_blocks_the_archive_and_aws_is_not_asked(arch):
    msg = categorised(arch, store_body=False)
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    html = c.get(reverse("message_detail", args=[msg.pk])).content.decode()
    assert "switched off" in html and reverse("sent_body", args=[msg.pk]) not in html
    assert open_text(c, msg).status_code == 400 and c.get(reverse("sent_body", args=[msg.pk])).status_code == 400 and arch.calls == []


def test_a_category_that_allows_reading_opens_normally(arch):
    msg = categorised(arch, store_body=True, body_retention_days=30)
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert "Hello Alice" in open_text(c, msg).content.decode()


def test_a_categorys_shorter_window_wins_over_the_global_one(arch):
    from apps.sesdata.models import MailCategory
    MailCategory.objects.create(name="billing", store_body=True, body_retention_days=2)
    msg = app_message(age=timedelta(days=3))
    Message.objects.filter(pk=msg.pk).update(mail_category="billing")
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert open_text(c, msg).status_code == 400 and arch.calls == []                    # 3 days old: inside the global 30, outside the category's 2


def test_a_categorys_longer_window_does_not_extend_the_global_one(arch):
    from apps.sesdata.models import MailCategory
    MailCategory.objects.create(name="billing", store_body=True, body_retention_days=365)
    msg = app_message(age=timedelta(days=31))
    Message.objects.filter(pk=msg.pk).update(mail_category="billing")
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert open_text(c, msg).status_code == 400


def test_a_categorys_redaction_rules_are_applied_and_a_bad_rule_is_ignored(arch):
    arch.content_body = {"Text": "Order ORD-48213 for Ann. Reference REF/99-1234."}
    msg = categorised(arch, store_body=True, redaction_rules=[r"ORD-\d+", r"REF/[\d-]+", "([unclosed"])
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    html = open_text(c, msg).content.decode()
    assert "ORD-48213" not in html and "REF/99-1234" not in html and "for Ann." in html and "[redacted]" in html


def test_mail_with_no_category_row_follows_the_global_settings(arch):
    msg = app_message()
    Message.objects.filter(pk=msg.pk).update(mail_category="not-a-configured-category")
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert "Hello Alice" in open_text(c, msg).content.decode()


# ---------------------------------------------------------------- redaction: the parser-differential cases
@pytest.mark.parametrize("raw, gone", [
    ("Open HTTPS://APP.EXAMPLE/go?Token=SECRET1234567", "SECRET1234567"),                              # upper-case scheme
    ("Open HTTPS://APP.EXAMPLE/go?foo=SECRET1234567", "SECRET1234567"),                                # upper-case scheme, ordinary parameter name
    ("Open https://app.example/go#access_token=SECRET1234567&x=1", "SECRET1234567"),                    # fragment
    ("Open https://app.example/go?a=1#frag-SECRET1234567", "SECRET1234567"),                            # query and fragment
    ("Token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk here", "eyJzdWIi"),
    ("Download https://files.example/d/abcdefghij.klmnopqrst.uvwxyz0123.pdf now", "abcdefghij.klmnop"),   # dots inside the opaque run
    ("Open https://app.example//Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA now", "Zm9vYmFy"),                          # empty first path segment: a double slash
    ("Open https://app.example/a//Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA now", "Zm9vYmFy"),                        # double slash inside the path
    ("Open https://app.example///Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA now", "Zm9vYmFy"),                         # triple slash
])
def test_more_ways_of_hiding_a_secret_in_a_link_are_masked(raw, gone):
    out = archive.redact_for_display(raw)
    assert gone not in out and "[redacted]" in out


@pytest.mark.parametrize("raw", [
    "see https://a-very-long-subdomain-name-for-tests.example.com/path/ok for details",              # a long host is not a token
    "open https://app.example/files/report.pdf",                                                     # a short file name stays
    "see https://app.example/billing/invoices/123?x=1".split("?")[0],
])
def test_ordinary_links_stay_readable(raw):
    assert archive.redact_for_display(raw) == raw
