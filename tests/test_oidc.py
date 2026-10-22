"""Sign-in callback: provider-neutral, identity bound to (issuer, subject), strict claims, fail-closed configuration."""
import os
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.management import call_command
from django.http import HttpResponseRedirect
from django.test import Client

from apps.accounts import views
from apps.accounts.models import User
from apps.audit.models import AuditLog

pytestmark = pytest.mark.django_db
ISS = "https://idp.example"
DISCOVERY = "https://idp.example/.well-known/openid-configuration"
GOOGLE = "https://accounts.google.com/.well-known/openid-configuration"


class FakeProvider:
    def __init__(self, claims=None, boom=False, issuer=ISS):
        self.claims, self.boom, self.issuer, self.redirect_kwargs = claims or {}, boom, issuer, None

    def authorize_access_token(self, request):
        if self.boom:
            raise RuntimeError("bad state")
        return {"userinfo": self.claims}

    def authorize_redirect(self, request, uri, **kw):
        self.redirect_kwargs = kw
        return HttpResponseRedirect("https://idp.example/authorize")

    def load_server_metadata(self):
        return {"issuer": self.issuer}


def run(monkeypatch, settings, claims, domain="", discovery=DISCOVERY, boom=False, issuer=ISS, defaults=True):
    settings.OIDC_ALLOWED_DOMAIN, settings.OIDC_DISCOVERY_URL = domain, discovery
    if defaults:  # a well-formed token unless the test overrides a claim
        claims = {"iss": ISS, "sub": "sub-" + (claims.get("email") or "x"), **claims}
    prov = FakeProvider(claims, boom, issuer)
    monkeypatch.setattr(views, "_google", lambda: prov)
    return Client(HTTP_HOST="console.test").get("/oidc/callback/"), prov


def good(email="ann@corp.example", **extra):
    return {"email": email, "email_verified": True, **extra}


def test_provisioned_user_signs_in_without_any_domain_restriction(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    r, _ = run(monkeypatch, settings, good("Ann@Corp.Example"))
    assert r.status_code == 302 and AuditLog.objects.filter(action="login.success").exists()


def test_unprovisioned_or_deactivated_user_is_denied_with_no_hint(monkeypatch, settings):
    assert run(monkeypatch, settings, good("stranger@corp.example"))[0].status_code == 403
    u = User.objects.create_user("gone@corp.example", role="viewer")
    u.is_active = False
    u.save()
    assert run(monkeypatch, settings, good("gone@corp.example"))[0].status_code == 403
    assert AuditLog.objects.filter(action="login.denied").count() == 2


# ---- identity binding: the e-mail only selects the account, (issuer, subject) decides ------------------
def test_first_sign_in_binds_the_provider_identity_and_later_ones_must_match(monkeypatch, settings):
    u = User.objects.create_user("ann@corp.example", role="viewer")
    assert run(monkeypatch, settings, good(sub="alice-1"))[0].status_code == 302
    u.refresh_from_db()
    assert (u.oidc_issuer, u.oidc_subject) == (ISS, "alice-1") and AuditLog.objects.filter(action="login.identity_bound").exists()
    assert run(monkeypatch, settings, good(sub="alice-1"))[0].status_code == 302


def test_same_email_with_a_different_subject_is_refused(monkeypatch, settings):
    """The e-mail takeover (a provider that lets someone assert another person's address) fails after the first bind."""
    User.objects.create_user("ann@corp.example", role="security_admin")
    assert run(monkeypatch, settings, good(sub="alice-1"))[0].status_code == 302
    attacker, _ = run(monkeypatch, settings, good(sub="mallory-9"))
    assert attacker.status_code == 403
    assert AuditLog.objects.filter(action="login.identity_mismatch", details__reason="different_subject").exists()


def test_a_provider_identity_cannot_be_bound_to_two_accounts(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    User.objects.create_user("bob@corp.example", role="viewer")
    assert run(monkeypatch, settings, good("ann@corp.example", sub="shared"))[0].status_code == 302
    r, _ = run(monkeypatch, settings, good("bob@corp.example", sub="shared"))
    assert r.status_code == 403 and AuditLog.objects.filter(details__reason="identity_bound_elsewhere").exists()


def test_a_different_issuer_with_the_same_subject_is_a_different_identity(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    assert run(monkeypatch, settings, good(sub="s1"))[0].status_code == 302
    r, _ = run(monkeypatch, settings, good(sub="s1", iss="https://other.example"), issuer="https://other.example")
    assert r.status_code == 403


def test_missing_issuer_or_subject_is_denied(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    assert run(monkeypatch, settings, {**good(), "sub": ""}, defaults=False)[0].status_code == 403
    assert run(monkeypatch, settings, {**good(), "iss": ISS}, defaults=False)[0].status_code == 403  # no sub at all
    assert run(monkeypatch, settings, {**good(), "sub": "s"}, defaults=False)[0].status_code == 403  # no iss at all


def test_operator_can_reset_a_binding(monkeypatch, settings):
    u = User.objects.create_user("ann@corp.example", role="viewer")
    run(monkeypatch, settings, good(sub="old"))
    call_command("create_console_user", "ann@corp.example", "--reset-identity")
    u.refresh_from_db()
    assert u.oidc_subject == "" and AuditLog.objects.filter(action="user.identity_reset").exists()
    assert run(monkeypatch, settings, good(sub="new"))[0].status_code == 302


# ---- claims are checked strictly --------------------------------------------------------------------------
@pytest.mark.parametrize("value,allowed", [(True, True), ("true", True), ("TRUE", True), (False, False), ("false", False), ("False", False), (None, False), (1, False), ("", False), ("yes", False)])
def test_email_verified_is_strict(monkeypatch, settings, value, allowed):
    """bool("false") is True in Python; a truthiness check would let an UNVERIFIED address in."""
    User.objects.create_user("ann@corp.example", role="viewer")
    r, _ = run(monkeypatch, settings, {"email": "ann@corp.example", "email_verified": value})
    assert (r.status_code == 302) is allowed


def test_missing_email_verified_claim_is_denied(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    assert run(monkeypatch, settings, {"email": "ann@corp.example"})[0].status_code == 403


def test_token_issuer_must_match_the_discovery_issuer(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    r, _ = run(monkeypatch, settings, good(iss="https://evil.example"))
    assert r.status_code == 403


def test_multi_tenant_templated_issuer_is_refused(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    templated = "https://login.example/{tenantid}/v2.0"
    r, _ = run(monkeypatch, settings, good(iss="https://login.example/abc/v2.0"), issuer=templated)
    assert r.status_code == 403


def test_google_issuer_may_appear_without_the_scheme(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    for iss in ("https://accounts.google.com", "accounts.google.com"):
        User.objects.filter(email="ann@corp.example").update(oidc_issuer="", oidc_subject="")
        r, _ = run(monkeypatch, settings, good(iss=iss, hd="corp.example"), domain="corp.example", discovery=GOOGLE, issuer="https://accounts.google.com")
        assert r.status_code == 302, iss


# ---- domain restriction ------------------------------------------------------------------------------------
def test_domain_restriction_when_configured(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    User.objects.create_user("eve@other.example", role="viewer")
    assert run(monkeypatch, settings, good("ann@corp.example"), domain="corp.example")[0].status_code == 302
    assert run(monkeypatch, settings, good("eve@other.example"), domain="corp.example")[0].status_code == 403
    assert run(monkeypatch, settings, good("ann@corp.example.evil.net"), domain="corp.example")[0].status_code == 403


def test_google_requires_matching_hosted_domain_claim(monkeypatch, settings):
    User.objects.create_user("ann@corp.example", role="viewer")
    kw = dict(domain="corp.example", discovery=GOOGLE, issuer="https://accounts.google.com")
    assert run(monkeypatch, settings, good(iss="https://accounts.google.com"), **kw)[0].status_code == 403  # no hd claim
    assert run(monkeypatch, settings, good(iss="https://accounts.google.com", hd="other.example"), **kw)[0].status_code == 403
    assert run(monkeypatch, settings, good(iss="https://accounts.google.com", hd="corp.example"), **kw)[0].status_code == 302


def test_provider_error_fails_closed(monkeypatch, settings):
    r, _ = run(monkeypatch, settings, {}, boom=True)
    assert r.status_code == 400 and AuditLog.objects.filter(action="login.failed").exists()


def test_hd_hint_is_only_sent_to_google(monkeypatch, settings):
    settings.OIDC_ALLOWED_DOMAIN = "corp.example"
    for url, expect in ((GOOGLE, {"hd": "corp.example"}), ("https://login.example/.well-known/openid-configuration", {})):
        settings.OIDC_DISCOVERY_URL = url
        prov = FakeProvider()
        monkeypatch.setattr(views, "_google", lambda p=prov: p)
        Client(HTTP_HOST="console.test").get("/oidc/start/")
        assert prov.redirect_kwargs == expect


# ---- start-up configuration is fail-closed -----------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent


def _import_settings(**env):
    base = {"PATH": os.environ["PATH"], "MC_SECRET_KEY": "x" * 40, "MC_DEBUG": "0", "MC_OIDC_CLIENT_ID": "abc", "MC_CONSOLE_HOST": "c.example"}
    proc = subprocess.run([sys.executable, "-c", "import config.settings"], cwd=ROOT, env={**base, **env}, capture_output=True, text=True)
    return proc.returncode, proc.stderr


def test_production_refuses_to_start_with_sign_in_but_no_domain_policy():
    code, err = _import_settings()
    assert code != 0 and "no domain policy" in err


def test_production_starts_with_a_domain_or_an_explicit_opt_in():
    assert _import_settings(MC_OIDC_ALLOWED_DOMAIN="corp.example")[0] == 0
    assert _import_settings(MC_OIDC_ALLOW_ANY_DOMAIN="1")[0] == 0


def test_no_sign_in_configured_does_not_trip_the_guard():
    assert _import_settings(MC_OIDC_CLIENT_ID="")[0] == 0
