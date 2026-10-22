"""Short-lived signed tokens for the cookie-less mailview origin.

The console (authenticated, capability-checked, audited) issues a token; the mailview origin
only verifies the signature. TTL is 60 s and the token is bound to the object and the user.
"""
from django.conf import settings
from django.core import signing

SALT = "mailview.v1"
TTL = 60


def issue(kind, obj_id, user_id):
    token = signing.dumps({"k": kind, "id": obj_id, "u": user_id}, salt=SALT, compress=False)
    scheme, host = ("http", f"{settings.MAILVIEW_HOST}:8000") if settings.DEBUG else ("https", settings.MAILVIEW_HOST)
    return f"{scheme}://{host}/mailview/{token}/"


def verify(token):
    """Returns the payload dict or raises signing.BadSignature / SignatureExpired."""
    try:
        payload = signing.loads(token, salt=SALT, max_age=TTL)
    except signing.BadSignature:
        raise
    except Exception as exc:  # malformed base64/JSON from a crafted token must be a 404, never a 500
        raise signing.BadSignature("malformed token") from exc
    if not isinstance(payload, dict) or payload.get("k") not in ("msg", "inbound") or not isinstance(payload.get("id"), int):
        raise signing.BadSignature("bad payload")
    return payload
