import json
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.compose import service
from apps.compose.models import Draft, SenderAddress, SentMail
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata.models import SuppressionEntry

from .test_aws_policies import _import_settings
from .test_views import login

pytestmark = pytest.mark.django_db
FROM = "notifications@corp.example"


@pytest.fixture
def on(settings):
    settings.SEND_ENABLED = True
    settings.SEND_FROM_ADDRESSES = [FROM, "support@corp.example"]
    settings.SEND_CONFIG_SET, settings.AWS_SEND_ROLE_ARN = "mc-set", "arn:aws:iam::123456789012:role/mail-console-send"
    settings.SEND_DEFAULT_REPLY_TO = "support@corp.example"
    settings.SEND_MAX_RECIPIENTS, settings.SEND_PER_USER_PER_HOUR, settings.SEND_PER_USER_PER_DAY, settings.SEND_PER_DAY = 5, 10, 20, 30
    SenderAddress.objects.create(address=FROM, enabled=True, display_name="Horilla")
    SenderAddress.objects.create(address="support@corp.example", enabled=False)
    return settings


class FakeSender:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def send(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise self.fail
        return "0100abc-msg-1"


@pytest.fixture
def ses(monkeypatch, on):
    fake = FakeSender()
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda region, email, rid: fake)
    return fake


def draft(user, **kw):
    d = dict(from_address=FROM, to_text="a@x.com", subject="Hello", body="Hi there")
    d.update(kw)
    return Draft.objects.create(user=user, **d)


def me(role=DELIVERABILITY_ADMIN, email="d@example.com", step_up=True, **extra):
    return login(role, email, step_up=step_up, **extra)


def go(user, d, region="ap-south-1"):
    p = service.prepare(d, region)
    return service.send(user, d.pk, service.content_hash(p), region)


def aws_error(code):
    return ClientError({"Error": {"Code": code, "Message": "secret AWS detail"}}, "SendEmail")


# ---------------------------------------------------------------- parsing and checks
@pytest.mark.parametrize("text,good,bad", [
    ("a@x.com, b@y.org\nc@z.io;d@w.net", ["a@x.com", "b@y.org", "c@z.io", "d@w.net"], []),
    ("Ann <ann@x.com>", ["ann@x.com"], []),
    ("A@x.com, a@X.com", ["A@x.com"], []),                                   # same address twice: one
    ("not-an-address, @x.com, a@", [], ["not-an-address", "@x.com", "a@"]),
    ("a@x.com\r\nBcc: evil@x.com", [], ["a@x.com", "Bcc: evil@x.com"]),        # a CR makes that entry bad, and a pasted label is never guessed at
    ("Bcc: evil@x.com", [], ["Bcc: evil@x.com"]), ("hello there a@x.com", [], ["hello there a@x.com"]), ("a@x.com b@x.com", [], ["a@x.com b@x.com"]),
    ("Ann <ann@x.com> extra", [], ["Ann <ann@x.com> extra"]), ("<a@x.com", [], ["<a@x.com"]), ("a@x.com>", [], ["a@x.com>"]),
    ("müller@x.com, a@münchen.de", [], ["müller@x.com", "a@münchen.de"]),    # ASCII only: that is what SES takes
    ("a@b@c.com", [], ["a@b@c.com"]),
])
def test_address_parsing(text, good, bad):
    got, rejected = service.parse_addresses(text)
    assert got == good and len(rejected) == len(bad)


def test_a_good_draft_is_ready_and_a_bad_one_lists_every_problem(on):
    _, u = me()
    assert service.prepare(draft(u)).ok
    p = service.prepare(draft(u, from_address="evil@elsewhere.com", to_text="", subject=" ", body=""))
    assert not p.ok and len(p.errors) == 4


def test_from_must_be_in_the_environment_and_switched_on(on):
    _, u = me()
    assert "not allowed" in service.prepare(draft(u, from_address="ceo@corp.example")).errors[0]
    assert "switched off" in service.prepare(draft(u, from_address="support@corp.example")).errors[0]
    SenderAddress.objects.filter(address=FROM).update(enabled=True)
    on.SEND_FROM_ADDRESSES = ["support@corp.example"]                         # removed from the environment: off here too
    assert not service.prepare(draft(u)).ok and service.usable_senders() == []


def test_header_injection_is_refused_in_subject_and_addresses(on):
    _, u = me()
    assert not service.prepare(draft(u, subject="Hello\r\nBcc: evil@x.com")).ok
    assert not service.prepare(draft(u, subject="Hello\nX-Evil: 1")).ok
    assert not service.prepare(draft(u, to_text="a@x.com\r\nBcc: evil@x.com")).ok



def test_limits_on_recipients_subject_and_body_and_duplicates(on):
    _, u = me()
    assert not service.prepare(draft(u, to_text=",".join(f"a{i}@x.com" for i in range(6)))).ok          # max is 5 here
    assert not service.prepare(draft(u, to_text="a@x.com", cc_text="A@x.com")).ok                       # repeated across fields
    assert not service.prepare(draft(u, subject="s" * 201)).ok and not service.prepare(draft(u, body="b" * 100_001)).ok


def test_suppressed_recipients_are_refused_with_a_clear_reason(on):
    _, u = me()
    SuppressionEntry.objects.create(aws_account_id="1", region="ap-south-1", address="Gone@x.com", address_lower="gone@x.com", reason="BOUNCE")
    p = service.prepare(draft(u, to_text="gone@x.com, ok@x.com"), "ap-south-1")
    assert not p.ok and "suppression list" in p.errors[0] and "Gone@x.com" in p.errors[0]


def test_from_header_has_a_safe_display_name_and_reply_to_falls_back_to_the_default(on):
    _, u = me()
    SenderAddress.objects.filter(address=FROM).update(display_name='Evil" <x@y>\r\nBcc: z', reply_to="")
    p = service.prepare(draft(u))
    assert p.from_header.endswith(f"<{FROM}>") and "\r" not in p.from_header and "\n" not in p.from_header and "x@y" not in p.from_header
    assert p.reply_to == "support@corp.example"


# ---------------------------------------------------------------- the HTML part cannot carry markup
def test_html_is_escaped_paragraphed_and_links_only_for_http_and_https():
    h = service.render_html('Hi <script>alert(1)</script> & "bye"\nsecond line\n\nSee https://ex.com/a?b=1&c=2. Also javascript:alert(1) and onerror=x')
    assert "<script>" not in h and "&lt;script&gt;" in h and "&amp;" in h
    assert h.count("<p>") == 2 and "<br>" in h
    assert '<a href="https://ex.com/a?b=1&amp;c=2">https://ex.com/a?b=1&amp;c=2</a>.' in h        # trailing full stop is not part of the link
    assert 'href="javascript' not in h and "<a " in h and h.count("<a ") == 1
    assert '"><img' not in service.render_html('https://x.com/"><img src=x onerror=alert(1)>')
    before = service.render_html("<img src=x onerror=alert(1)> look at https://ex.com <b>now</b>")        # markup BEFORE and AFTER a link
    assert "<img" not in before and "<b>" not in before and "&lt;img" in before and "&lt;b&gt;" in before


# ---------------------------------------------------------------- sending
def test_a_send_sends_exactly_what_was_previewed_and_records_it(ses):
    _, u = me()
    sent = go(u, draft(u, to_text="a@x.com", cc_text="b@x.com", bcc_text="c@x.com", body="Line one\n\nhttps://ex.com"))
    (call,) = ses.calls
    assert call["from_address"] == f"Horilla <{FROM}>" and call["to"] == ["a@x.com"] and call["cc"] == ["b@x.com"] and call["bcc"] == ["c@x.com"]
    assert call["reply_to"] == "support@corp.example" and call["config_set"] == "mc-set" and "https://ex.com" in call["html"] and call["text"].startswith("Line one")
    assert sent.ses_message_id == "0100abc-msg-1" and sent.recipient_count == 3 and sent.user_email == "d@example.com"
    assert not Draft.objects.exists()


def test_the_audit_row_has_who_what_and_how_many_but_not_the_body_or_the_addresses(ses):
    _, u = me()
    go(u, draft(u, to_text="private.person@x.com", body="THE SECRET BODY TEXT"))
    row = AuditLog.objects.get(action="compose.sent")
    assert row.actor == "d@example.com" and row.target == "0100abc-msg-1" and row.details["recipients"] == 1 and row.details["from"] == FROM
    assert "SECRET" not in json.dumps(row.details) and "private.person" not in json.dumps(row.details)


def test_changed_after_preview_is_refused_and_nothing_is_sent(ses):
    _, u = me()
    d = draft(u)
    h = service.content_hash(service.prepare(d))
    Draft.objects.filter(pk=d.pk).update(body="Something else entirely")
    with pytest.raises(service.SendError, match="changed after you previewed"):
        service.send(u, d.pk, h, "ap-south-1")
    assert not ses.calls and Draft.objects.get().state == Draft.DRAFT


def test_a_draft_can_only_be_sent_once_even_if_submitted_twice(ses):
    _, u = me()
    d = draft(u)
    h = service.content_hash(service.prepare(d))
    service.send(u, d.pk, h, "ap-south-1")
    with pytest.raises(Draft.DoesNotExist):
        service.send(u, d.pk, h, "ap-south-1")
    assert len(ses.calls) == 1 and SentMail.objects.count() == 1


def test_a_draft_already_sending_cannot_be_sent_again(ses):
    _, u = me()
    d = draft(u, state=Draft.SENDING)
    with pytest.raises(service.SendError, match="already being sent"):
        service.send(u, d.pk, service.content_hash(service.prepare(d)), "ap-south-1")
    assert not ses.calls


def test_someone_elses_draft_cannot_be_sent(ses):
    _, mine = me()
    _, other = me(email="o@example.com")
    d = draft(other)
    with pytest.raises(Draft.DoesNotExist):
        service.send(mine, d.pk, service.content_hash(service.prepare(d)), "ap-south-1")
    assert not ses.calls


def test_limits_stop_a_send_and_count_recipients(ses):
    _, u = me()
    for _ in range(2):                                                         # 2 x 5 recipients = the hourly 10
        go(u, draft(u, to_text=",".join(f"r{i}@x.com" for i in range(5))))
    with pytest.raises(service.SendError, match="hourly limit"):
        go(u, draft(u))
    assert len(ses.calls) == 2 and service.limits("d@example.com")["hour_left"] == 0
    SentMail.objects.update(sent_at=timezone.now() - timedelta(hours=2))        # an hour later the hourly window has cleared
    assert service.limits("d@example.com")["hour_left"] == 10 and service.limits("d@example.com")["day_left"] == 10


def test_the_everyone_limit_applies_across_people(ses, on):
    on.SEND_PER_DAY = 6
    _, a = me(email="a@example.com")
    _, b = me(email="b@example.com")
    go(a, draft(a, to_text=",".join(f"r{i}@x.com" for i in range(5))))
    with pytest.raises(service.SendError, match="everyone"):
        go(b, draft(b, to_text="x@y.com,z@y.com"))


def test_aws_saying_no_restores_the_draft_and_never_shows_aws_text(monkeypatch, on):
    _, u = me()
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda *a: FakeSender(fail=aws_error("MessageRejected")))
    d = draft(u)
    with pytest.raises(service.SendError) as e:
        go(u, d)
    assert "secret AWS detail" not in str(e.value) and Draft.objects.get().state == Draft.DRAFT and not SentMail.objects.exists()
    assert AuditLog.objects.get(action="compose.send_failed").details["error"] == "MessageRejected"


def test_a_failure_to_assume_the_role_is_a_clean_no(monkeypatch, on):
    _, u = me()

    def boom(*a):
        raise aws_error("AccessDenied")
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", boom)
    with pytest.raises(service.SendError, match="send role"):
        go(u, draft(u))
    assert Draft.objects.get().state == Draft.DRAFT


def test_a_lost_answer_is_unknown_not_failed_and_blocks_a_second_send(monkeypatch, on):
    _, u = me()
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda *a: FakeSender(fail=ReadTimeoutError(endpoint_url="https://email.example")))
    d = draft(u)
    with pytest.raises(service.SendError, match="MAY have been sent"):
        go(u, d)
    assert Draft.objects.get().state == Draft.UNKNOWN and not SentMail.objects.exists()
    with pytest.raises(service.SendError, match="Check Sent mail"):
        service.send(u, d.pk, service.content_hash(service.prepare(d)), "ap-south-1")
    assert AuditLog.objects.filter(action="compose.send_unknown").exists()


def test_a_send_stuck_in_sending_is_treated_as_unknown_after_a_while(ses):
    _, u = me()
    d = draft(u, state=Draft.SENDING)
    assert service.effective_state(d) == Draft.SENDING
    Draft.objects.filter(pk=d.pk).update(updated_at=timezone.now() - timedelta(minutes=5))
    assert service.effective_state(Draft.objects.get()) == Draft.UNKNOWN


def test_the_ses_client_never_retries_so_a_lost_response_cannot_double_send(monkeypatch, on):
    from apps.sesdata import aws
    seen = {}

    class Sts:
        def assume_role(self, **kw):
            seen["assume"] = kw
            return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}

    def client(svc, **kw):
        if svc == "sts":
            return Sts()
        seen["ses"] = kw
        return object()
    monkeypatch.setattr(aws.boto3, "client", client)
    on.AWS_WRITE_ROLE_EXTERNAL_ID = "s" * 30
    aws.assume_sender("ap-south-1", "ann@corp.example", "9")
    assert seen["assume"]["RoleArn"].endswith("role/mail-console-send") and seen["assume"]["SourceIdentity"] == "ann@corp.example" and seen["assume"]["ExternalId"] == "s" * 30
    assert seen["ses"]["config"].retries["max_attempts"] == 1


def test_the_sender_object_can_only_send_one_simple_message():
    from apps.sesdata.aws import SesSender
    assert not [m for m in dir(SesSender) if not m.startswith("_") and m != "send"]    # no bulk, raw or template methods exist


def test_ses_call_shape_is_simple_content_with_tag_and_config_set():
    from apps.sesdata.aws import SesSender
    seen = {}

    class C:
        def send_email(self, **kw):
            seen.update(kw)
            return {"MessageId": "m1"}
    assert SesSender(C()).send(from_address="A <a@x.com>", to=["b@x.com"], cc=[], bcc=[], reply_to=None, subject="S", text="T", html="<p>T</p>", config_set="mc") == "m1"
    assert set(seen["Content"]) == {"Simple"} and seen["ConfigurationSetName"] == "mc" and seen["EmailTags"] == [{"Name": "mc-app", "Value": "compose"}]
    assert "CcAddresses" not in seen["Destination"] and "ReplyToAddresses" not in seen


# ---------------------------------------------------------------- the pages
def test_compose_does_not_exist_unless_switched_on(settings):
    settings.SEND_ENABLED = False
    c, _ = me()
    for name in ("compose", "compose_new", "compose_senders"):
        assert c.get(reverse(name)).status_code == 404
    assert "Compose" not in c.get(reverse("dashboard")).content.decode()


def test_only_admins_see_compose_and_only_security_admins_the_address_settings(on):
    for role in (VIEWER, SUPPORT):
        c, _ = me(role, f"{role}@example.com")
        assert c.get(reverse("compose")).status_code == 403 and c.post(reverse("compose_new"), {}).status_code == 403
    d, _ = me(DELIVERABILITY_ADMIN, "dd@example.com")
    assert d.get(reverse("compose")).status_code == 200 and d.get(reverse("compose_senders")).status_code == 403
    s, _ = me(SECURITY_ADMIN, "ss@example.com")
    assert s.get(reverse("compose_senders")).status_code == 200 and "Compose" in s.get(reverse("dashboard")).content.decode()


def test_write_save_preview_and_send_through_the_pages(ses):
    c, u = me()
    r = c.post(reverse("compose_new"), {"from_address": FROM, "to": "a@x.com", "subject": "Hi", "body": "Body", "action": "save"})
    d = Draft.objects.get()
    assert r.status_code == 302 and d.to_text == "a@x.com"
    r = c.post(reverse("compose_edit", args=[d.pk]), {"from_address": FROM, "to": "a@x.com", "subject": "Hi", "body": "Body text", "action": "preview"})
    assert r["Location"] == reverse("compose_preview", args=[d.pk])
    page = c.get(reverse("compose_preview", args=[d.pk])).content.decode()
    h = page.split('name="hash" value="')[1].split('"')[0]
    assert "Body text" in page and f"Horilla &lt;{FROM}&gt;" in page
    assert c.post(reverse("compose_send", args=[d.pk]), {"hash": h}).status_code == 302
    assert len(ses.calls) == 1 and SentMail.objects.get().subject == "Hi"
    assert "0100abc-msg-1" in c.get(reverse("compose")).content.decode()


def test_preview_and_send_need_a_fresh_passkey_and_a_get_on_send_just_goes_back_to_the_preview(ses):
    c, u = me(step_up=False)
    d = draft(u)
    r = c.get(reverse("compose_preview", args=[d.pk]))
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up"))
    assert c.post(reverse("compose_send", args=[d.pk]), {"hash": "x"})["Location"].startswith(reverse("step_up")) and not ses.calls
    c2, u2 = me(email="e@example.com")
    d2 = draft(u2)
    assert c2.get(reverse("compose_send", args=[d2.pk]))["Location"] == reverse("compose_preview", args=[d2.pk])


def test_the_editor_reports_errors_and_does_not_continue_to_preview(on):
    c, _ = me()
    r = c.post(reverse("compose_new"), {"from_address": "bad@elsewhere.com", "to": "x", "subject": "", "body": "", "action": "preview"})
    html = r.content.decode()
    assert r.status_code == 200 and "Fix these before sending" in html and "not allowed" in html and "not a valid address" in html


def test_drafts_are_private_and_only_the_owner_can_open_or_delete_them(on):
    c1, u1 = me(email="one@example.com")
    c2, u2 = me(email="two@example.com")
    d = draft(u1, subject="Private plans")
    assert "Private plans" not in c2.get(reverse("compose")).content.decode()
    for url, method in ((reverse("compose_edit", args=[d.pk]), "get"), (reverse("compose_preview", args=[d.pk]), "get"),
                        (reverse("compose_delete", args=[d.pk]), "post"), (reverse("compose_release", args=[d.pk]), "post")):
        assert getattr(c2, method)(url).status_code == 404, url
    assert Draft.objects.filter(pk=d.pk).exists()
    assert c1.post(reverse("compose_delete", args=[d.pk])).status_code == 302 and not Draft.objects.exists()


def test_the_draft_count_is_capped(on):
    c, u = me()
    for _ in range(service.MAX_DRAFTS_PER_USER):
        draft(u)
    c.post(reverse("compose_new"), {"from_address": FROM, "subject": "one more", "action": "save"})
    assert Draft.objects.count() == service.MAX_DRAFTS_PER_USER


def test_releasing_an_unknown_draft_needs_a_passkey_is_audited_and_only_applies_to_unknown(on):
    c, u = me()
    unknown, plain = draft(u, state=Draft.UNKNOWN), draft(u, subject="fine")
    assert c.post(reverse("compose_release", args=[plain.pk])).status_code == 302 and not AuditLog.objects.filter(action="compose.unknown_released").exists()
    assert c.post(reverse("compose_release", args=[unknown.pk])).status_code == 302
    assert Draft.objects.get(pk=unknown.pk).state == Draft.DRAFT and AuditLog.objects.filter(action="compose.unknown_released").count() == 1
    nopk, _ = me(email="n@example.com", step_up=False)
    u3 = Draft.objects.create(user=_, from_address=FROM, state=Draft.UNKNOWN)
    assert nopk.post(reverse("compose_release", args=[u3.pk]))["Location"].startswith(reverse("step_up"))


# ---------------------------------------------------------------- sending addresses
def test_security_admin_edits_addresses_with_a_passkey_and_it_is_audited(on):
    c, _ = me(SECURITY_ADMIN, "s@example.com")
    posted = {"enabled_0": "on", "name_0": 'Horilla <script>"', "reply_0": "Help@Corp.example", "name_1": "Support", "enabled_1": "on"}
    SenderAddress.objects.get(address="support@corp.example").delete()
    SenderAddress.objects.create(address="support@corp.example")
    r = c.post(reverse("compose_senders"), posted)
    assert r.status_code == 302
    row = SenderAddress.objects.get(address=FROM)
    assert row.enabled and row.display_name == "Horilla script" and row.reply_to == "help@corp.example" and row.updated_by == "s@example.com"
    a = AuditLog.objects.get(action="compose.senders_updated")
    assert FROM in a.details["changes"]
    c2, _ = me(SECURITY_ADMIN, "s2@example.com", step_up=False)
    assert c2.post(reverse("compose_senders"), posted)["Location"].startswith(reverse("step_up"))


def test_bad_reply_to_is_rejected_and_nothing_is_saved(on):
    c, _ = me(SECURITY_ADMIN, "s@example.com")
    r = c.post(reverse("compose_senders"), {"enabled_0": "on", "reply_0": "not an address"})
    assert r.status_code == 200 and "Reply-To must be one valid address" in r.content.decode()
    assert SenderAddress.objects.get(address=FROM).reply_to == "" and not AuditLog.objects.filter(action="compose.senders_updated").exists()


def test_addresses_start_switched_off_and_removed_ones_cannot_send(on):
    SenderAddress.objects.all().delete()
    on.SEND_FROM_ADDRESSES = [FROM, "new@corp.example"]
    service.sync_senders()
    assert not SenderAddress.objects.filter(enabled=True).exists() and service.usable_senders() == []


# ---------------------------------------------------------------- start-up validation
def test_enabled_compose_refuses_to_start_when_misconfigured():
    base = dict(MC_SEND_ENABLED="1", MC_SEND_FROM_ADDRESSES="n@corp.example", MC_SEND_CONFIG_SET="mc-set",
                MC_AWS_SEND_ROLE_ARN="arn:aws:iam::123456789012:role/mail-console-send", MC_AWS_WRITE_ROLE_EXTERNAL_ID="s" * 30)
    assert _import_settings(**base)[0] == 0
    for change, needle in (({"MC_SEND_FROM_ADDRESSES": ""}, "MC_SEND_FROM_ADDRESSES"), ({"MC_SEND_FROM_ADDRESSES": "*@corp.example"}, "MC_SEND_FROM_ADDRESSES"),
                           ({"MC_SEND_CONFIG_SET": ""}, "MC_SEND_CONFIG_SET"), ({"MC_AWS_SEND_ROLE_ARN": "nope"}, "MC_AWS_SEND_ROLE_ARN"),
                           ({"MC_AWS_WRITE_ROLE_EXTERNAL_ID": ""}, "EXTERNAL_ID"), ({"MC_SEND_DEFAULT_REPLY_TO": "bad"}, "REPLY_TO"),
                           ({"MC_SEND_MAX_RECIPIENTS": "0"}, "limits"), ({"MC_SEND_MAX_RECIPIENTS": "500"}, "limits"),
                           ({"MC_SEND_PER_USER_PER_DAY": "5", "MC_SEND_PER_USER_PER_HOUR": "9"}, "limits")):
        code, err = _import_settings(**{**base, **change})
        assert code != 0 and needle in err, (change, err[-250:])
    assert _import_settings()[0] == 0   # off by default: nothing is required


def test_a_nul_byte_in_any_field_is_removed_on_save_instead_of_crashing(on):
    c, _ = me()
    r = c.post(reverse("compose_new"), {"from_address": FROM, "to": "a@x.com\x00", "subject": "Hi\x00", "body": "Bo\x00dy", "action": "save"})
    d = Draft.objects.get()
    assert r.status_code == 302 and (d.to_text, d.subject, d.body) == ("a@x.com", "Hi", "Body")
