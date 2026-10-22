import time

import pytest
from django.core import signing
from django.test import Client
from django.urls import reverse

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.inbound.tokens import SALT, issue
from apps.sesdata.ingest import process_body
from apps.sesdata.models import AccountSnapshot, Message

from . import factories as f

pytestmark = pytest.mark.django_db
TOPICS = [f.TOPIC]
PAGES = ["dashboard", "messages", "suppression", "identities", "config_sets", "alerts"]


def login(role, email=None, step_up=False, **extra):
    u = User.objects.create_user(email or f"{role}@example.com", role=role, **extra)
    c = Client(HTTP_HOST="console.test")
    c.force_login(u)
    s = c.session
    s["session_started"] = s["last_seen"] = s["login_at"] = time.time()
    if step_up:
        s["step_up_at"] = time.time()
    s.save()
    return c, u


def test_anonymous_is_redirected_everywhere():
    c = Client(HTTP_HOST="console.test")
    for name in PAGES + ["audit", "approvals", "users"]:
        r = c.get(reverse(name))
        assert r.status_code == 302 and r["Location"].startswith("/login/")


@pytest.mark.parametrize("name", PAGES)
def test_every_page_renders_for_viewer(name):
    c, _ = login(VIEWER)
    process_body(f.sns(f.send()), TOPICS)
    AccountSnapshot.objects.create(aws_account_id="1", region="ap-south-1")
    r = c.get(reverse(name))
    assert r.status_code == 200


def test_security_headers_and_csp_nonce():
    c, _ = login(VIEWER)
    r = c.get(reverse("dashboard"))
    csp = r["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp and "script-src 'self' 'nonce-" in csp
    assert r["Cache-Control"] == "no-store" and r["X-Content-Type-Options"] == "nosniff" and r["X-Frame-Options"] == "DENY"
    html = r.content.decode()
    import re
    # Executable inline scripts are blocked by the CSP; JSON data blocks (json_script) are inert and allowed.
    assert not re.search(r'<script(?![^>]*(?:\ssrc=|type="application/json"))', html), "inline <script> would be blocked by the CSP"
    assert 'name="htmx-config"' in html and '"allowEval":false' in html


def test_viewer_blocked_from_governance_pages():
    c, _ = login(VIEWER)
    for name in ("audit", "approvals", "users"):
        assert c.get(reverse(name)).status_code == 403


def test_viewer_cannot_post_suppression_removal():
    c, _ = login(VIEWER)
    assert c.post(reverse("suppression_remove"), {"addresses": "a@x.com", "reason": "r"}).status_code == 403


def test_writes_require_fresh_passkey_step_up():
    c, _ = login(SUPPORT)
    r = c.post(reverse("suppression_remove"), {"addresses": "a@x.com", "reason": "r"})
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up"))
    c2, _ = login(SUPPORT, "sup2@example.com", step_up=True)
    r2 = c2.post(reverse("suppression_remove"), {"addresses": "", "reason": "r"})
    assert r2.status_code == 302 and r2["Location"] == reverse("suppression")  # reached the handler (validation error)


def test_stale_step_up_is_rejected(settings):
    c, _ = login(SUPPORT)
    s = c.session
    s["step_up_at"] = time.time() - settings.STEP_UP_MAX_AGE - 5
    s.save()
    assert c.post(reverse("suppression_remove"), {"addresses": "a@x.com", "reason": "r"})["Location"].startswith(reverse("step_up"))


def test_idle_session_is_logged_out(settings):
    c, _ = login(VIEWER)
    s = c.session
    s["last_seen"] = time.time() - settings.SESSION_IDLE_TIMEOUT - 5
    s.save()
    assert c.get(reverse("dashboard")).status_code == 302


def test_domain_scope_hides_other_domains_messages():
    process_body(f.sns(f.send(mid="mA")), TOPICS)  # from example.com
    ev = f.send(mid="mB")
    ev["mail"]["source"] = "x@other.com"
    process_body(f.sns(ev), TOPICS)
    c, _ = login(VIEWER, scope_domains=["other.com"])
    body = c.get(reverse("messages")).content.decode()
    assert Message.objects.count() == 2
    other = Message.objects.get(ses_message_id="mB")
    mine = Message.objects.get(ses_message_id="mA")
    assert c.get(reverse("message_detail", args=[other.pk])).status_code == 200
    assert c.get(reverse("message_detail", args=[mine.pk])).status_code == 404
    assert str(mine.pk) not in body or "mA" not in body


def test_message_detail_shows_bounce_explainer():
    for e in (f.send(), f.bounce(sub="OnAccountSuppressionList")):
        process_body(f.sns(e), TOPICS)
    c, _ = login(VIEWER)
    html = c.get(reverse("message_detail", args=[Message.objects.get().pk])).content.decode()
    assert "YOUR account suppression list" in html and "550 5.1.1" in html


def test_body_reveal_needs_reason_stepup_and_is_audited():
    process_body(f.sns(f.send()), TOPICS)
    m = Message.objects.get()
    m.body_ref = "bodies/x.eml"
    m.save()
    c, _ = login(SUPPORT, step_up=True)
    assert c.post(reverse("message_body", args=[m.pk]), {"reason": ""}).status_code == 400
    r = c.post(reverse("message_body", args=[m.pk]), {"reason": "customer ticket 4411"})
    assert r.status_code == 200 and b"mailview" in r.content
    assert AuditLog.objects.filter(action="body.view").exists()
    viewer, _ = login(VIEWER, "v2@example.com", step_up=True)
    assert viewer.post(reverse("message_body", args=[m.pk]), {"reason": "x"}).status_code == 403


def test_user_admin_cannot_remove_last_security_admin_or_self_demote():
    c, me = login(SECURITY_ADMIN, step_up=True)
    r = c.post(reverse("user_update", args=[me.pk]), {"role": VIEWER, "active": "1"}, follow=True)
    assert User.objects.get(pk=me.pk).role == SECURITY_ADMIN
    other = User.objects.create_user("o@example.com", role=SUPPORT)
    c.post(reverse("user_update", args=[other.pk]), {"role": DELIVERABILITY_ADMIN, "active": "1"})
    assert User.objects.get(pk=other.pk).role == DELIVERABILITY_ADMIN
    assert AuditLog.objects.filter(action="user.updated").exists()


def test_dev_login_is_unreachable_when_not_debug():
    User.objects.create_user("d@example.com", role=SECURITY_ADMIN)
    assert Client(HTTP_HOST="console.test").get("/dev-login/?email=d@example.com").status_code == 404


def test_login_next_open_redirect_is_neutralised():
    r = Client(HTTP_HOST="console.test").get("/login/?next=https://evil.example/")
    assert b"evil.example" not in r.content


# ---- mailview origin isolation ----------------------------------------------------
def test_mailview_host_serves_nothing_but_mailview():
    c = Client(HTTP_HOST="mailview.test")
    assert c.get("/").status_code == 404 and c.get("/messages/").status_code == 404 and c.get("/login/").status_code == 404


def test_console_host_does_not_serve_mailview():
    assert Client(HTTP_HOST="console.test").get("/mailview/anything/").status_code == 404


def test_mailview_rejects_bad_and_expired_tokens():
    c = Client(HTTP_HOST="mailview.test")
    assert c.get("/mailview/garbage/").status_code == 404
    old = signing.TimestampSigner(salt=SALT)  # wrong shape on purpose
    assert c.get(f"/mailview/{old.sign('x')}/").status_code == 404


def test_mailview_token_is_short_lived(monkeypatch):
    from apps.inbound import tokens
    tok = issue("msg", 1, 1).rstrip("/").rsplit("/", 1)[1]
    assert tokens.verify(tok)["id"] == 1
    real = time.time
    monkeypatch.setattr(signing.time, "time", lambda: real() + tokens.TTL + 5)
    with pytest.raises(signing.SignatureExpired):
        tokens.verify(tok)


def test_mailview_response_is_locked_down(monkeypatch):
    from apps.inbound import bodies
    from apps.inbound.mime import ParsedMail
    process_body(f.sns(f.send()), TOPICS)
    m = Message.objects.get()
    m.body_ref = "bodies/x.eml"
    m.save()
    evil = ParsedMail(html_clean="<p>hello</p>", text="")
    monkeypatch.setattr(bodies, "load_message_body", lambda ref, rules=(): evil)
    tok = issue("msg", m.pk, 1).rstrip("/").rsplit("/", 1)[1]
    r = Client(HTTP_HOST="mailview.test").get(f"/mailview/{tok}/")
    assert r.status_code == 200
    csp = r["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "sandbox" in csp and "frame-ancestors" in csp and "script-src" not in csp
    assert r["Cache-Control"] == "no-store" and "Set-Cookie" not in r.headers and not r.cookies
