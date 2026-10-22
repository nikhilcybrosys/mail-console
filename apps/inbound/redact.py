"""Redact secrets in message text before storing or showing it.

Applied on ingest AND at render time (defense in depth). Reveal of the raw value is a separate,
permissioned, audited action; this module only ever removes information.
"""
import re

MASK = "[redacted]"

# URL query values for secret-looking parameter names.
_SECRET_PARAM = re.compile(
    r"([?&;](?:token|key|secret|sig|signature|code|otp|password|pwd|auth|access_token|id_token|reset|verify|confirm|hash)=)[^&\s\"'<>]+",
    re.I)
# Long opaque path segments typical of reset / magic links: /reset/<token>
_PATH_TOKEN = re.compile(r"(/(?:reset|verify|confirm|activate|invite|magic|unsubscribe|accept|token|auth)[a-z_-]*/)[A-Za-z0-9_\-.~]{16,}", re.I)
# "code: 123456" / "OTP is 123456" / "verification code 123-456"
_OTP = re.compile(r"((?:code|otp|pin|passcode)\W{0,12}(?:is\W{0,3})?)(\d{4,8}|\d{3}[- ]\d{3})\b", re.I)
_BEARER = re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/-]{16,}=*", re.I)
_AWS_KEY = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")

DEFAULT_RULES = [
    (_SECRET_PARAM, r"\1" + MASK),
    (_PATH_TOKEN, r"\1" + MASK),
    (_OTP, r"\1" + MASK),
    (_BEARER, r"\1" + MASK),
    (_AWS_KEY, MASK),
]


def redact_text(text, extra_rules=()):
    if not text:
        return text
    for pat, repl in DEFAULT_RULES:
        text = pat.sub(repl, text)
    for rule in extra_rules:  # category-specific regex strings; invalid ones are ignored, never raised
        try:
            text = re.sub(rule, MASK, text)
        except re.error:
            continue
    return text
