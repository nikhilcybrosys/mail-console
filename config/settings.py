"""Settings for the Mail Console.

Every secret comes from the environment (injected by ECS from Secrets Manager).
Nothing here reads a .env file on purpose: never `source` env files.
"""
import os
import re
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and val in (None, ""):
        raise RuntimeError(f"Missing required environment variable {name}")
    return val


def env_float(name, default):
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be a number, got {raw!r}") from None


def env_bool(name, default=False):
    return str(os.environ.get(name, str(default))).lower() in ("1", "true", "yes", "on")


DEBUG = env_bool("MC_DEBUG", False)
# In production SECRET_KEY must be provided; a throwaway key is only allowed in DEBUG/tests.
SECRET_KEY = env("MC_SECRET_KEY", "dev-insecure-key-not-for-production" if DEBUG else None, required=not DEBUG)

CONSOLE_HOST = env("MC_CONSOLE_HOST", "localhost")
MAILVIEW_HOST = env("MC_MAILVIEW_HOST", "mailview.localhost")  # separate registrable domain in prod
ALLOWED_HOSTS = [h for h in {CONSOLE_HOST, MAILVIEW_HOST, *env("MC_EXTRA_HOSTS", "").split(",")} if h]
if DEBUG:
    ALLOWED_HOSTS += ["localhost", "127.0.0.1", "testserver"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "apps.core",
    "apps.accounts",
    "apps.audit",
    "apps.sesdata",
    "apps.approvals",
    "apps.inbound",
    "apps.compose",
    "apps.console",
]

MIDDLEWARE = [
    "apps.core.middleware.HealthCheckMiddleware",  # first: answers /healthz/ for any Host
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "apps.core.middleware.HostRoutingMiddleware",  # mailview host only serves the renderer
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.accounts.middleware.SessionHardeningMiddleware",  # idle timeout + absolute lifetime
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.SecurityHeadersMiddleware",  # CSP with nonce, permissions-policy, etc.
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context.console_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("MC_DB_NAME", "mailconsole"),
        "USER": env("MC_DB_USER", "mailconsole"),
        "PASSWORD": env("MC_DB_PASSWORD", ""),
        "HOST": env("MC_DB_HOST", "127.0.0.1"),
        "PORT": env("MC_DB_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {"sslmode": env("MC_DB_SSLMODE", "prefer" if DEBUG else "require")},
        "TEST": {"NAME": env("MC_DB_TEST_NAME", "mailconsole_test")},
    }
}

AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
# Local passwords are disabled for real users (set_unusable_password); SSO only.
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 14}},
]

# --- OpenID Connect sign-in (any standards-compliant provider) --------------
OIDC_CLIENT_ID = env("MC_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = env("MC_OIDC_CLIENT_SECRET", "")
# Optional: only accept e-mail addresses at this domain. Users must still be provisioned in the console.
OIDC_ALLOWED_DOMAIN = env("MC_OIDC_ALLOWED_DOMAIN", "").lower().lstrip("@")
# Any OIDC provider's discovery URL (Google, Okta, Microsoft Entra, Keycloak, Authentik...). Defaults to Google.
OIDC_DISCOVERY_URL = env("MC_OIDC_DISCOVERY_URL", "https://accounts.google.com/.well-known/openid-configuration")
OIDC_ALLOW_ANY_DOMAIN = env_bool("MC_OIDC_ALLOW_ANY_DOMAIN", False)
if not DEBUG and OIDC_CLIENT_ID and not OIDC_ALLOWED_DOMAIN and not OIDC_ALLOW_ANY_DOMAIN:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured(
        "Sign-in is configured but has no domain policy. Set MC_OIDC_ALLOWED_DOMAIN to your organisation's e-mail domain, "
        "or set MC_OIDC_ALLOW_ANY_DOMAIN=1 to deliberately accept any verified e-mail (users must still be provisioned, and "
        "each is bound to the provider's issuer and subject on first sign-in).")
# Dev-only login shortcut. Refused unless DEBUG is on (enforced again in the view).
DEV_LOGIN_ENABLED = DEBUG and env_bool("MC_DEV_LOGIN", False)

# --- Sessions / cookies ------------------------------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "__Host-mcsession" if not DEBUG else "mcsession"
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 8 * 3600  # absolute 8 h (also enforced by middleware)
SESSION_IDLE_TIMEOUT = 30 * 60  # 30 min idle
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = False  # HTMX reads it via hx-headers; token is also in <body>
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_TRUSTED_ORIGINS = [f"https://{CONSOLE_HOST}"]
STEP_UP_MAX_AGE = 10 * 60  # passkey assertion must be this fresh for writes / body reveal

SECURE_SSL_REDIRECT = env_bool("MC_SSL_REDIRECT", not DEBUG)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")  # behind the ALB only
SECURE_HSTS_SECONDS = 0 if DEBUG else 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
# Preload-list submission is a deliberate, hard-to-undo opt-in, so it is off unless you set MC_HSTS_PRELOAD=1.
SECURE_HSTS_PRELOAD = env_bool("MC_HSTS_PRELOAD", False)
SILENCED_SYSTEM_CHECKS = [] if SECURE_HSTS_PRELOAD else ["security.W021"]
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

# --- WebAuthn (step-up) --------------------------------------------------------
WEBAUTHN_RP_ID = env("MC_WEBAUTHN_RP_ID", CONSOLE_HOST)
WEBAUTHN_RP_NAME = env("MC_BRAND_NAME", "Mail Console")
WEBAUTHN_ORIGIN = env("MC_WEBAUTHN_ORIGIN", f"https://{CONSOLE_HOST}")

# --- AWS -------------------------------------------------------------------------
AWS_REGIONS = [r for r in env("MC_AWS_REGIONS", "ap-south-1").split(",") if r]
# ECS task roles supply credentials; never static keys. These ARNs are the write roles
# the web task assumes per approved action (see apps/sesdata/aws.py).
AWS_WRITE_ROLE_OPS_ARN = env("MC_AWS_WRITE_ROLE_OPS_ARN", "")
AWS_WRITE_ROLE_SECURITY_ARN = env("MC_AWS_WRITE_ROLE_SECURITY_ARN", "")
AWS_ASSUME_SESSION_SECONDS = 900
# A shared secret the write roles require (sts:ExternalId) on top of the named person. It keeps other programs that happen to
# run on the same server, and can reach the instance credentials, from assuming the write roles: only the console knows it.
AWS_WRITE_ROLE_EXTERNAL_ID = env("MC_AWS_WRITE_ROLE_EXTERNAL_ID", "")
if not DEBUG and (AWS_WRITE_ROLE_OPS_ARN or AWS_WRITE_ROLE_SECURITY_ARN) and not AWS_WRITE_ROLE_EXTERNAL_ID:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured("Write roles are configured but MC_AWS_WRITE_ROLE_EXTERNAL_ID is not set. The write roles require it: "
                               "aws/render.py generates one (see aws/README.md).")
# --- Compose: hand-written one-off mail (OFF unless MC_SEND_ENABLED) -------------------------------------------------
# The AWS send role is the real lock: it can call only SendEmail, only for named people, only from the addresses in its
# policy. MC_SEND_FROM_ADDRESSES is the console's mirror of that list (what it will ever offer); a security admin then
# switches individual addresses on or off on the "Sending addresses" page. Adding an address needs the AWS policy changed too.
SEND_ENABLED = env_bool("MC_SEND_ENABLED", False)
SEND_FROM_ADDRESSES = [a.strip().lower() for a in env("MC_SEND_FROM_ADDRESSES", "").split(",") if a.strip()]
SEND_CONFIG_SET = env("MC_SEND_CONFIG_SET", "")                # mail goes through this set, so every send shows up in Sent mail
AWS_SEND_ROLE_ARN = env("MC_AWS_SEND_ROLE_ARN", "")
SEND_DEFAULT_REPLY_TO = env("MC_SEND_DEFAULT_REPLY_TO", "").strip().lower()
SEND_MAX_RECIPIENTS = int(env_float("MC_SEND_MAX_RECIPIENTS", 10))              # To + Cc + Bcc in one message
SEND_PER_USER_PER_HOUR = int(env_float("MC_SEND_PER_USER_PER_HOUR", 20))        # recipients per person
SEND_PER_USER_PER_DAY = int(env_float("MC_SEND_PER_USER_PER_DAY", 100))
SEND_PER_DAY = int(env_float("MC_SEND_PER_DAY", 300))                           # recipients, everyone together
SEND_MAX_SUBJECT = 200
SEND_MAX_BODY = 100_000
if SEND_ENABLED:
    _addr = re.compile(r"[a-z0-9._%+-]{1,64}@([a-z0-9-]+\.)+[a-z]{2,}")
    _problems = []
    if not SEND_FROM_ADDRESSES or not all(_addr.fullmatch(a) for a in SEND_FROM_ADDRESSES):
        _problems.append("MC_SEND_FROM_ADDRESSES must list plain addresses, comma separated (no wildcards)")
    if not SEND_CONFIG_SET:
        _problems.append("MC_SEND_CONFIG_SET must name the configuration set mail is sent through")
    if not re.fullmatch(r"arn:aws:iam::\d{12}:role/[\w+=,.@/-]+", AWS_SEND_ROLE_ARN):
        _problems.append("MC_AWS_SEND_ROLE_ARN must be the send role's ARN")
    if not AWS_WRITE_ROLE_EXTERNAL_ID:
        _problems.append("MC_AWS_WRITE_ROLE_EXTERNAL_ID must be set: the send role requires the same shared secret")
    if SEND_DEFAULT_REPLY_TO and not _addr.fullmatch(SEND_DEFAULT_REPLY_TO):
        _problems.append("MC_SEND_DEFAULT_REPLY_TO must be a plain address")
    if not (1 <= SEND_MAX_RECIPIENTS <= 50 and SEND_PER_USER_PER_HOUR >= 1 and SEND_PER_USER_PER_DAY >= SEND_PER_USER_PER_HOUR and SEND_PER_DAY >= SEND_PER_USER_PER_DAY):
        _problems.append("send limits must be positive, MC_SEND_MAX_RECIPIENTS at most 50, and hour <= per-person day <= everyone day")
    if _problems:
        raise ImproperlyConfigured("Compose is enabled but not configured correctly: " + "; ".join(_problems) + ".")

SQS_EVENTS_QUEUE_URL = env("MC_SQS_EVENTS_QUEUE_URL", "")
SQS_INBOUND_QUEUE_URL = env("MC_SQS_INBOUND_QUEUE_URL", "")
EXPECTED_SNS_TOPIC_ARNS = [a for a in env("MC_EXPECTED_SNS_TOPIC_ARNS", "").split(",") if a]
AUDIT_BUCKET = env("MC_AUDIT_BUCKET", "")
CONTENT_BUCKET = env("MC_CONTENT_BUCKET", "")
MAIL_ARCHIVE_ID = env("MC_MAIL_ARCHIVE_ID", "")

# --- Business rules (tunable, but defaults are deliberate) ------------------------
BULK_SUPPRESSION_APPROVAL_THRESHOLD = 50
try:
    EXPORT_MAX_ROWS = int(os.environ.get("MC_EXPORT_MAX_ROWS", "50000"))  # a CSV export refuses to start above this many messages (or addresses)
except ValueError:
    EXPORT_MAX_ROWS = 0
if not 1 <= EXPORT_MAX_ROWS <= 1_000_000:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured("MC_EXPORT_MAX_ROWS must be a whole number between 1 and 1000000.")
APPROVAL_TTL_HOURS = 24
BODY_REVEAL_REQUIRES_REASON = True
# Rates are fractions: 0.02 = 2%. SES itself reviews accounts at about 5% bounces and 0.1% complaints.
ALERT_THRESHOLDS = {
    "bounce_warn": env_float("MC_ALERT_BOUNCE_WARN", 0.02), "bounce_page": env_float("MC_ALERT_BOUNCE_PAGE", 0.04),
    "complaint_warn": env_float("MC_ALERT_COMPLAINT_WARN", 0.0005), "complaint_page": env_float("MC_ALERT_COMPLAINT_PAGE", 0.0008),
    "quota_warn": env_float("MC_ALERT_QUOTA_WARN", 0.80),
}
for _kind in ("bounce", "complaint"):
    if not 0 < ALERT_THRESHOLDS[f"{_kind}_warn"] < ALERT_THRESHOLDS[f"{_kind}_page"] <= 1:
        raise ImproperlyConfigured(f"MC_ALERT_{_kind.upper()}_WARN must be above 0 and below MC_ALERT_{_kind.upper()}_PAGE, and both at most 1 (fractions, 0.02 = 2%).")
if not 0 < ALERT_THRESHOLDS["quota_warn"] <= 1:
    raise ImproperlyConfigured("MC_ALERT_QUOTA_WARN must be above 0 and at most 1.")
ALERT_MIN_SAMPLE = int(env_float("MC_ALERT_MIN_SAMPLE", 200))          # no account-wide rate alert below this many sends in 24h
ALERT_APP_MIN_SAMPLE = int(env_float("MC_ALERT_APP_MIN_SAMPLE", 50))   # ... and none for one sender app below this many
# "No events" alert: wait this long, but at least as long as GAP_FACTOR times the usual gap between sends (capped), so a
# sender that mails a few times a day is not reported as silent between mails.
ALERT_SILENT_MIN_MINUTES = int(env_float("MC_ALERT_SILENT_MIN_MINUTES", 60))
ALERT_SILENT_GAP_FACTOR = env_float("MC_ALERT_SILENT_GAP_FACTOR", 3.0)
ALERT_SILENT_MAX_HOURS = env_float("MC_ALERT_SILENT_MAX_HOURS", 24.0)

# Notification channels. Alerts always appear in the console; these push them elsewhere. https only.
ALERT_SLACK_WEBHOOK_URL = env("MC_ALERT_SLACK_WEBHOOK_URL", "")
ALERT_WEBHOOK_URL = env("MC_ALERT_WEBHOOK_URL", "")            # generic JSON webhook (any tool that accepts a POST)
ALERT_WEBHOOK_SECRET = env("MC_ALERT_WEBHOOK_SECRET", "")      # optional: signs each request (see README, Alerts)
ALERT_QUIET_HOURS = env("MC_ALERT_QUIET_HOURS", "")            # e.g. "22:00-07:00": warnings wait; urgent alerts never do
ALERT_QUIET_TZ = env("MC_ALERT_QUIET_TZ", "UTC")
ALERT_NOTIFY_RESOLVED = env_bool("MC_ALERT_NOTIFY_RESOLVED", True)
for _name, _url in (("MC_ALERT_SLACK_WEBHOOK_URL", ALERT_SLACK_WEBHOOK_URL), ("MC_ALERT_WEBHOOK_URL", ALERT_WEBHOOK_URL)):
    # Alert text can name addresses and domains: never send it over plain http (a local test receiver in DEBUG is fine).
    if _url and not (_url.startswith("https://") or (DEBUG and re.match(r"http://(localhost|127\.0\.0\.1)[:/]", _url))):
        raise ImproperlyConfigured(f"{_name} must be an https:// URL.")
_QUIET = re.fullmatch(r"(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})", ALERT_QUIET_HOURS.strip()) if ALERT_QUIET_HOURS.strip() else None
if ALERT_QUIET_HOURS.strip():
    if not _QUIET or not all(int(_QUIET[i]) < (24 if i in (1, 3) else 60) for i in (1, 2, 3, 4)):
        raise ImproperlyConfigured("MC_ALERT_QUIET_HOURS must look like 22:00-07:00 (24-hour clock).")
    try:
        ZoneInfo(ALERT_QUIET_TZ)
    except ZoneInfoNotFoundError:
        raise ImproperlyConfigured(f"MC_ALERT_QUIET_TZ {ALERT_QUIET_TZ!r} is not a known time zone (use e.g. Asia/Kolkata).") from None

# Prometheus scrape endpoint (/metrics). Off unless a token is set; aggregate numbers only, never addresses or subjects.
METRICS_TOKEN = env("MC_METRICS_TOKEN", "")
if METRICS_TOKEN and len(METRICS_TOKEN) < 32:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured("MC_METRICS_TOKEN must be at least 32 characters (try: python -c 'import secrets; print(secrets.token_urlsafe(32))').")
METRICS_CACHE_SECONDS = 10  # one database pass per this many seconds, however many scrapers ask

# --- White-labelling: name, logo and accent are configurable ------------------------------
BRAND_NAME = env("MC_BRAND_NAME", "Mail Console")
BRAND_LOGO = env("MC_BRAND_LOGO", "brand/mark.svg")  # static path; dark variant used on dark theme
BRAND_LOGO_DARK = env("MC_BRAND_LOGO_DARK", "brand/mark-white.svg")
BRAND_ACCENT = env("MC_BRAND_ACCENT", "")  # optional #RRGGBB; must give >= 4.5:1 with white text or it is ignored
OIDC_PROVIDER_NAME = env("MC_OIDC_PROVIDER_NAME", "SSO")  # shown on the sign-in button

WORKER_HEARTBEAT_FILE = env("MC_WORKER_HEARTBEAT_FILE", "/tmp/worker.heartbeat")

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"] if (BASE_DIR / "static").exists() else []
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
                    if not DEBUG else "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
USE_I18N = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-us"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"format": '{"ts":"%(asctime)s","lvl":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"handlers": ["console"], "level": env("MC_LOG_LEVEL", "INFO")},
}
# Message bodies / recipient lists must never be logged; log ids only.
