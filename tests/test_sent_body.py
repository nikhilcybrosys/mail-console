"""The text of Compose mail: kept only when asked for, shown only to admins with a reason and a passkey, audited, and aged out."""
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.compose import service
from apps.compose.models import SentMail
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata.ingest import process_body
from apps.sesdata.models import BodyAccessLog, Message

from . import factories as f
from .test_compose import FROM, FakeSender, aws_error, draft, go, me, on, ses  # noqa: F401  (fixtures)
from .test_views import login

pytestmark = pytest.mark.django_db
TOPICS = [f.TOPIC]
MID = "0100abc-msg-1"                     # what FakeSender returns as the SES message id
BODY = "Hello Ann,\n\nThe invoice is attached.\n\n<script>alert(1)</script>"
ROOT = Path(__file__).resolve().parent.parent


def send_one(user, settings, days=90, body=BODY, **kw):
    settings.SEND_KEEP_BODY_DAYS = days
    d = draft(user, body=body, **kw)
    go(user, d)
    return SentMail.objects.get()


def ses_message(mid=MID, domain_src="support@example.com"):
    process_body(f.sns(f.send(mid=mid)), TOPICS)       # the "send" event SES publishes for the same message id
    return Message.objects.get(ses_message_id=mid)


# ---------------------------------------------------------------- what is stored
def test_nothing_is_stored_by_default(ses, settings):
    _, u = me()
    assert settings.SEND_KEEP_BODY_DAYS == 0
    sent = send_one(u, settings, days=0)
    assert sent.body == "" and sent.subject == "Hello"


def test_the_text_and_reply_to_are_stored_when_switched_on(ses, settings):
    _, u = me()
    sent = send_one(u, settings)
    assert sent.body == BODY and sent.reply_to == "support@corp.example"      # the same cleaned text that was sent
    assert ses.calls[0]["subject"] == "Hello"


def test_only_the_plain_text_the_author_wrote_is_stored_not_the_html_that_was_built(ses, settings):
    _, u = me()
    sent = send_one(u, settings)
    assert "<p>" not in sent.body and "<div" not in sent.body


def test_a_failed_or_unknown_send_stores_nothing(monkeypatch, on, settings):
    _, u = me()
    settings.SEND_KEEP_BODY_DAYS = 90
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda region, email, rid: FakeSender(fail=aws_error("MessageRejected")))
    with pytest.raises(service.SendError):
        go(u, draft(u))
    assert not SentMail.objects.exists()


# ---------------------------------------------------------------- who can open it
def open_it(client, msg, reason="customer asked what we sent"):
    return client.post(reverse("sent_body", args=[msg.pk]), {"reason": reason})


@pytest.mark.parametrize("role", [DELIVERABILITY_ADMIN, SECURITY_ADMIN])
def test_deliverability_and_security_admins_can_open_it_and_see_everything_escaped(ses, settings, role):
    c, u = me(role, f"{role}@example.com")
    send_one(u, settings, cc_text="c@x.com", bcc_text="b@x.com")
    r = open_it(c, ses_message())
    html = r.content.decode()
    assert r.status_code == 200 and "The invoice is attached." in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html          # shown, never rendered
    assert "notifications@corp.example" in html and "support@corp.example" in html and "b@x.com" in html and u.email in html


@pytest.mark.parametrize("role", [VIEWER, SUPPORT])
def test_viewers_and_support_cannot_open_it(ses, settings, role):
    _, admin = me()
    send_one(admin, settings)
    msg = ses_message()
    c, _ = login(role, f"{role}@example.com", step_up=True)
    assert open_it(c, msg).status_code == 403
    assert not BodyAccessLog.objects.exists()


def test_it_needs_a_fresh_passkey_check(ses, settings):
    _, admin = me()
    send_one(admin, settings)
    msg = ses_message()
    c, _ = me(DELIVERABILITY_ADMIN, "nostep@example.com", step_up=False)
    r = open_it(c, msg)
    assert r.status_code == 302 and reverse("step_up") in r["Location"] and not BodyAccessLog.objects.exists()


def test_it_needs_a_reason_and_a_get_only_asks_for_one_without_showing_or_logging_anything(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    assert open_it(c, msg, reason="   ").status_code == 400
    r = c.get(reverse("sent_body", args=[msg.pk]))
    html = r.content.decode()
    assert r.status_code == 200 and "Why do you need to read this email?" in html and "The invoice is attached." not in html
    assert not BodyAccessLog.objects.exists() and not AuditLog.objects.filter(action="sent_body.view").exists()


def test_after_the_passkey_check_the_person_lands_on_a_page_that_works(ses, settings):
    """Step-up sends people back with a GET: the reason page must accept it (a POST-only view ended on 'method not allowed')."""
    _, u = me()
    send_one(u, settings)
    msg = ses_message()
    c, _ = me(DELIVERABILITY_ADMIN, "fresh@example.com", step_up=False)
    r = c.get(reverse("sent_body", args=[msg.pk]))
    assert r.status_code == 302 and reverse("step_up") in r["Location"] and f"/messages/{msg.pk}/sent-body/" in r["Location"].replace("%2F", "/")
    c2, _ = me(DELIVERABILITY_ADMIN, "fresh2@example.com", step_up=True)           # as after the passkey check
    assert c2.get(reverse("sent_body", args=[msg.pk])).status_code == 200


def test_a_get_for_a_message_with_no_stored_text_or_out_of_scope_is_refused(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    assert c.get(reverse("sent_body", args=[ses_message(mid="from-another-app").pk])).status_code == 400
    s, _ = me(DELIVERABILITY_ADMIN, "scoped2@example.com", scope_domains=["other.example"])
    assert s.get(reverse("sent_body", args=[msg.pk])).status_code == 404


def test_every_view_is_logged_with_the_reason_but_never_the_text(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    open_it(c, msg, reason="ticket 4411")
    (log,) = BodyAccessLog.objects.all()
    assert (log.user_email, log.message_id, log.reason) == (u.email, msg.pk, "ticket 4411")
    (a,) = AuditLog.objects.filter(action="sent_body.view")
    assert a.details["reason"] == "ticket 4411" and "invoice" not in str(a.details) and "invoice" not in str(a.target)


def test_the_response_is_not_cacheable(ses, settings):
    c, u = me()
    send_one(u, settings)
    assert "no-store" in open_it(c, ses_message())["Cache-Control"]


def test_a_person_limited_to_other_domains_gets_a_404(ses, settings):
    _, admin = me()
    send_one(admin, settings)
    msg = ses_message()
    c, _ = me(DELIVERABILITY_ADMIN, "scoped@example.com", scope_domains=["other.example"])
    assert open_it(c, msg).status_code == 404 and not BodyAccessLog.objects.exists()


def test_a_message_that_did_not_come_from_compose_has_no_text_to_open():
    c, _ = me()
    msg = ses_message(mid="from-another-app")
    assert open_it(c, msg).status_code == 400


def test_text_that_has_aged_out_cannot_be_opened(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    SentMail.objects.update(body="")
    assert open_it(c, msg).status_code == 400


# ---------------------------------------------------------------- what the Body tab says
def tab(client, msg):
    return client.get(reverse("message_detail", args=[msg.pk])).content.decode()


def test_the_body_tab_offers_the_text_to_admins_only(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    html = tab(c, msg)
    assert reverse("sent_body", args=[msg.pk]) in html and "Open the message text" in html and "90 days" in html
    assert 'name="reason"' not in html                                                  # the reason is asked for on its own page, after the passkey check
    assert "The invoice is attached." not in html                                       # never in the page itself
    v, _ = login(VIEWER, "v@example.com")
    html = tab(v, msg)
    assert reverse("sent_body", args=[msg.pk]) not in html and "Only deliverability and security admins can open it." in html


def test_the_body_tab_explains_aged_out_and_switched_off(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    SentMail.objects.update(body="")
    assert "no longer stored" in tab(c, msg)
    settings.SEND_KEEP_BODY_DAYS = 0
    assert "was not stored" in tab(c, msg) and "switched off" in tab(c, msg)


def test_mail_from_other_apps_keeps_the_old_explanation():
    c, _ = me()
    assert "No body stored for this message" in tab(c, ses_message(mid="other-app"))


def test_the_drawer_shows_the_same_tab(ses, settings):
    c, u = me()
    send_one(u, settings)
    msg = ses_message()
    html = c.get(reverse("message_drawer", args=[msg.pk])).content.decode()
    assert reverse("sent_body", args=[msg.pk]) in html


# ---------------------------------------------------------------- ageing out
def aged(settings, days_old, keep=90):
    settings.SEND_KEEP_BODY_DAYS = keep
    SentMail.objects.create(user_email="a@x.com", from_address=FROM, to_addrs=["t@x.com"], subject=f"s{days_old}", recipient_count=1,
                            ses_message_id=f"id{days_old}", body="secret text", reply_to="r@x.com")
    SentMail.objects.filter(ses_message_id=f"id{days_old}").update(sent_at=timezone.now() - timedelta(days=days_old))


def test_old_text_is_blanked_and_recent_text_and_all_metadata_stay(settings):
    aged(settings, 91), aged(settings, 89)
    assert service.prune_bodies() == 1
    old, new = SentMail.objects.get(ses_message_id="id91"), SentMail.objects.get(ses_message_id="id89")
    assert old.body == "" and (old.subject, old.to_addrs, old.reply_to, old.user_email) == ("s91", ["t@x.com"], "r@x.com", "a@x.com")
    assert new.body == "secret text"
    assert service.prune_bodies() == 0                                                   # nothing left to do


def test_the_boundary_is_exactly_the_keep_period(settings):
    aged(settings, 90, keep=90)
    SentMail.objects.update(sent_at=timezone.now() - timedelta(days=90, seconds=-5))     # five seconds younger than 90 days
    assert service.prune_bodies() == 0
    SentMail.objects.update(sent_at=timezone.now() - timedelta(days=90, seconds=5))
    assert service.prune_bodies() == 1


def test_switching_it_off_blanks_everything_at_the_next_run(settings):
    aged(settings, 1), aged(settings, 5)
    settings.SEND_KEEP_BODY_DAYS = 0
    assert service.prune_bodies() == 2 and not SentMail.objects.exclude(body="").exists()


def test_the_state_sync_job_does_the_pruning(settings):
    aged(settings, 91)
    call_command("sync_ses_state", "--skip-dns", "--skip-suppression")
    assert SentMail.objects.get().body == ""


# ---------------------------------------------------------------- configuration
def _settings_error(value):
    import os
    base = {"MC_SECRET_KEY": "x" * 60, "MC_DEBUG": "0", "MC_CONSOLE_HOST": "console.test", "MC_MAILVIEW_HOST": "mailview.test", "MC_DB_PORT": "54329",
            "MC_WEBAUTHN_ORIGIN": "https://console.test", "MC_SEND_ENABLED": "1", "MC_SEND_FROM_ADDRESSES": "a@corp.example", "MC_SEND_CONFIG_SET": "s",
            "MC_AWS_SEND_ROLE_ARN": "arn:aws:iam::123456789012:role/mail-console-send", "MC_AWS_WRITE_ROLE_EXTERNAL_ID": "y" * 32, "MC_SEND_KEEP_BODY_DAYS": value}
    code = "import os; os.environ['DJANGO_SETTINGS_MODULE']='config.settings'; from config import settings; print(settings.SEND_KEEP_BODY_DAYS)"
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env={**os.environ, **base}, capture_output=True, text=True)


def test_the_keep_period_is_validated_at_start_up():
    assert _settings_error("90").stdout.strip() == "90" and _settings_error("0").stdout.strip() == "0"
    for bad in ("-1", "3651"):
        proc = _settings_error(bad)
        assert proc.returncode != 0 and "MC_SEND_KEEP_BODY_DAYS" in proc.stderr


def test_the_migrations_match_the_models():
    from io import StringIO
    out = StringIO()
    try:
        call_command("makemigrations", "--check", "--dry-run", stdout=out, stderr=out)
    except SystemExit:
        pytest.fail("models and migrations differ: " + out.getvalue())
