"""Thin wrapper over python-fido2 for passkey registration and step-up assertions."""
from django.conf import settings
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)
from django.utils import timezone

from .models import WebAuthnCredential


def _server():
    rp = PublicKeyCredentialRpEntity(id=settings.WEBAUTHN_RP_ID, name=settings.WEBAUTHN_RP_NAME)
    return Fido2Server(rp, verify_origin=lambda origin: origin == settings.WEBAUTHN_ORIGIN)


def _creds(user):
    return [AttestedCredentialData(bytes(c.credential_data)) for c in user.passkeys.all()]


def begin_registration(user):
    entity = PublicKeyCredentialUserEntity(id=str(user.pk).encode(), name=user.email, display_name=user.name or user.email)
    options, state = _server().register_begin(
        entity, _creds(user), user_verification=UserVerificationRequirement.REQUIRED
    )
    return dict(options), state


def complete_registration(user, state, response, name="passkey"):
    auth_data = _server().register_complete(state, response)
    WebAuthnCredential.objects.create(user=user, name=name[:100], credential_data=bytes(auth_data.credential_data))


def begin_assertion(user):
    options, state = _server().authenticate_begin(_creds(user), user_verification=UserVerificationRequirement.REQUIRED)
    return dict(options), state


def complete_assertion(user, state, response):
    """Raises on failure. Returns the matched credential."""
    matched = _server().authenticate_complete(state, _creds(user), response)
    WebAuthnCredential.objects.filter(user=user).update(last_used_at=timezone.now())
    return matched
