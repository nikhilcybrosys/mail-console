"""Checks for adding a person, shared by the console's Add-person form."""
import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from apps.core.rbac import ROLES

from .models import User

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_USERS = 200


def parse_scope(text):
    """-> (domains, bad). Comma, semicolon, space or newline separated registrable-looking domains, lowercased, de-duplicated."""
    domains, bad = [], []
    for raw in re.split(r"[,;\s]+", text or ""):
        d = raw.strip().lower().lstrip("@")
        if not d:
            continue
        if not _DOMAIN.match(d):
            bad.append(raw[:40])
        elif d not in domains:
            domains.append(d)
    return domains, bad


def check_new_user(email, role, name, scope_text):
    """-> (clean dict, errors). Nothing is created here."""
    errors = []
    email = (email or "").strip().lower()
    name = _CONTROL.sub(" ", (name or "")).strip()[:100]
    try:
        if not email or not email.isascii() or email.count("@") != 1 or len(email) > 254 or re.search(r"\s", email):
            raise ValidationError("bad")
        validate_email(email)
    except ValidationError:
        errors.append("Enter a valid e-mail address.")
        email = ""
    if email:
        allowed = settings.OIDC_ALLOWED_DOMAIN
        if allowed and email.split("@")[1] != allowed:
            errors.append(f"Sign-in is limited to @{allowed}, so this person could not sign in. Use an address on that domain.")
        if User.objects.filter(email__iexact=email).exists():
            errors.append("That person already has an account. Change their role in the table below.")
    if role not in ROLES:
        errors.append("Choose a role.")
    scope, bad = parse_scope(scope_text)
    if bad:
        errors.append(f"Not a valid domain: {', '.join(bad[:3])}.")
    if User.objects.count() >= MAX_USERS:
        errors.append(f"At most {MAX_USERS} people.")
    return {"email": email, "role": role, "name": name, "scope": scope}, errors
