"""Settings for the Mail Console.

Every secret comes from the environment (injected by ECS from Secrets Manager).
Nothing here reads a .env file on purpose: never `source` env files.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and val in (None, ""):
        raise RuntimeError(f"Missing required environment variable {name}")
    return val


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
SQS_EVENTS_QUEUE_URL = env("MC_SQS_EVENTS_QUEUE_URL", "")
SQS_INBOUND_QUEUE_URL = env("MC_SQS_INBOUND_QUEUE_URL", "")
EXPECTED_SNS_TOPIC_ARNS = [a for a in env("MC_EXPECTED_SNS_TOPIC_ARNS", "").split(",") if a]
AUDIT_BUCKET = env("MC_AUDIT_BUCKET", "")
CONTENT_BUCKET = env("MC_CONTENT_BUCKET", "")
MAIL_ARCHIVE_ID = env("MC_MAIL_ARCHIVE_ID", "")

# --- Business rules (tunable, but defaults are deliberate) ------------------------
BULK_SUPPRESSION_APPROVAL_THRESHOLD = 50
APPROVAL_TTL_HOURS = 24
BODY_REVEAL_REQUIRES_REASON = True
ALERT_THRESHOLDS = {
    "bounce_warn": 0.02, "bounce_page": 0.04,
    "complaint_warn": 0.0005, "complaint_page": 0.0008,
    "quota_warn": 0.80,
}
ALERT_SLACK_WEBHOOK_URL = env("MC_ALERT_SLACK_WEBHOOK_URL", "")  # from Secrets Manager

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
