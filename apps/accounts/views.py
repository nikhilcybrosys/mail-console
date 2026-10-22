import json
import time

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import login, logout
from django.db import IntegrityError, transaction
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from apps.audit.service import record

from . import webauthn
from .models import User

oauth = OAuth()
_registered = False


def _google():
    global _registered
    if not _registered:
        oauth.register(
            "google", client_id=settings.OIDC_CLIENT_ID, client_secret=settings.OIDC_CLIENT_SECRET,
            server_metadata_url=settings.OIDC_DISCOVERY_URL,
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
        )
        _registered = True
    return oauth.google


def _is_google():
    return "accounts.google.com" in settings.OIDC_DISCOVERY_URL


def _safe_next(request, default="/"):
    nxt = request.GET.get("next") or request.POST.get("next") or default
    ok = url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure())
    return nxt if ok else default


def login_page(request):
    return render(request, "accounts/login.html", {"next": _safe_next(request), "dev_login": settings.DEV_LOGIN_ENABLED})


def oidc_start(request):
    request.session["post_login_next"] = _safe_next(request)
    redirect_uri = request.build_absolute_uri("/oidc/callback/")
    extra = {"hd": settings.OIDC_ALLOWED_DOMAIN} if (settings.OIDC_ALLOWED_DOMAIN and _is_google()) else {}  # Google-only hint
    return _google().authorize_redirect(request, redirect_uri, **extra)


def oidc_callback(request):
    provider = _google()
    try:
        token = provider.authorize_access_token(request)
        claims = token.get("userinfo") or {}
    except Exception:
        record("login.failed", request=request, details={"reason": "oidc_error"})
        return HttpResponseBadRequest("Sign-in failed")
    email = (claims.get("email") or "").lower()
    ok = _email_verified(claims.get("email_verified")) and "@" in email and _issuer_ok(claims, provider)
    domain = settings.OIDC_ALLOWED_DOMAIN
    if ok and domain:
        ok = email.endswith("@" + domain) and (claims.get("hd", "").lower() == domain if _is_google() else True)
    user = _identify(request, claims, email) if ok else None
    if user is None:
        # Same message for "wrong domain", "not provisioned" and "different identity": do not reveal which.
        record("login.denied", actor=email or "unknown", request=request, details={"domain_ok": ok})
        return render(request, "accounts/denied.html", status=403)
    return _finish_login(request, user)


def _email_verified(value):
    """True only for a real boolean true or the exact string "true" (some providers send a string).

    bool("false") is True in Python, so a truthiness test would accept an UNVERIFIED address.
    """
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _issuer_ok(claims, provider):
    """The token's issuer must be the single issuer in the provider's discovery document.

    Multi-tenant endpoints advertise a templated issuer (for example .../{tenantid}/v2.0) that cannot be pinned, so
    they are refused: use a tenant-specific discovery URL instead.
    """
    try:
        issuer = (provider.load_server_metadata() or {}).get("issuer", "")
    except Exception:
        return False
    if not issuer or "{" in issuer:
        return False
    allowed = {issuer} | ({"accounts.google.com"} if issuer == "https://accounts.google.com" else set())
    return claims.get("iss") in allowed


def _identify(request, claims, email):
    """Return the provisioned user this provider identity belongs to, or None.

    The e-mail only selects the candidate account. Access is decided by the provider's stable (issuer, subject): the
    first successful sign-in binds it to the account (atomically, so two racing first sign-ins cannot both win);
    every later sign-in must present the same pair, otherwise it is refused and audited.
    """
    iss, sub = (claims.get("iss") or "")[:255], (claims.get("sub") or "")[:255]
    if not iss or not sub:
        return None
    candidate = User.objects.filter(email=email, is_active=True).first()
    if candidate is None:
        return None
    if not candidate.oidc_subject:
        try:
            with transaction.atomic():
                bound = User.objects.filter(pk=candidate.pk, oidc_subject="").update(oidc_issuer=iss, oidc_subject=sub)
        except IntegrityError:  # this provider identity is already bound to a different account
            record("login.identity_mismatch", actor=email, request=request, details={"issuer": iss, "reason": "identity_bound_elsewhere"})
            return None
        if bound:
            record("login.identity_bound", actor=email, request=request, details={"issuer": iss})
            candidate.refresh_from_db()
        else:  # another request bound it first: fall through to the comparison below
            candidate.refresh_from_db()
    if (candidate.oidc_issuer, candidate.oidc_subject) != (iss, sub):
        record("login.identity_mismatch", actor=email, request=request, details={"issuer": iss, "reason": "different_subject"})
        return None
    return candidate


def _finish_login(request, user):
    nxt = request.session.pop("post_login_next", "/")
    request.session.cycle_key()
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["session_started"] = request.session["last_seen"] = request.session["login_at"] = time.time()
    request.session.pop("step_up_at", None)
    record("login.success", request=request)
    return redirect(nxt)


def dev_login(request):
    # Double-gated: setting AND DEBUG. Never reachable in production.
    if not (settings.DEBUG and settings.DEV_LOGIN_ENABLED):
        raise Http404
    email = (request.GET.get("email") or "").lower()
    user = User.objects.filter(email=email, is_active=True).first()
    if not user:
        raise Http404
    return _finish_login(request, user)


@require_POST
def logout_view(request):
    record("logout", request=request)
    logout(request)
    return redirect("/login/")


# ---- passkeys / step-up -----------------------------------------------------------
def _json(request):
    try:
        return json.loads(request.body or b"{}")
    except ValueError:
        return None


def step_up_page(request):
    if not request.user.is_authenticated:
        return redirect("/login/")
    return render(request, "accounts/step_up.html", {
        "has_passkey": request.user.passkeys.exists(), "next": _safe_next(request),
        "fresh_login": time.time() - request.session.get("login_at", 0) < 600,
    })


@require_POST
def step_up_begin(request):
    if not request.user.is_authenticated or not request.user.passkeys.exists():
        return JsonResponse({"error": "no passkey"}, status=400)
    options, state = webauthn.begin_assertion(request.user)
    request.session["webauthn_state"] = state
    return JsonResponse(options)


@require_POST
def step_up_complete(request):
    data, state = _json(request), request.session.pop("webauthn_state", None)
    if not request.user.is_authenticated or data is None or state is None:
        return JsonResponse({"error": "invalid"}, status=400)
    try:
        webauthn.complete_assertion(request.user, state, data)
    except Exception:
        record("stepup.failed", request=request)
        return JsonResponse({"error": "verification failed"}, status=400)
    request.session["step_up_at"] = time.time()
    record("stepup.success", request=request)
    return JsonResponse({"ok": True})


@require_POST
def passkey_register_begin(request):
    # Registering a credential is itself sensitive: require a login within the last 10 minutes,
    # or an existing fresh step-up if the user already has a passkey.
    u = request.user
    if not u.is_authenticated:
        return JsonResponse({"error": "auth"}, status=403)
    fresh_login = time.time() - request.session.get("login_at", 0) < 600
    if not (fresh_login or u.has_fresh_step_up(request.session)):
        return JsonResponse({"error": "recent authentication required"}, status=403)
    options, state = webauthn.begin_registration(u)
    request.session["webauthn_state"] = state
    return JsonResponse(options)


@require_POST
def passkey_register_complete(request):
    data, state = _json(request), request.session.pop("webauthn_state", None)
    if not request.user.is_authenticated or data is None or state is None:
        return JsonResponse({"error": "invalid"}, status=400)
    try:
        webauthn.complete_registration(request.user, state, data, name=str(data.get("name", "passkey")))
    except Exception:
        return JsonResponse({"error": "verification failed"}, status=400)
    request.session["step_up_at"] = time.time()
    record("passkey.registered", request=request)
    return JsonResponse({"ok": True})
