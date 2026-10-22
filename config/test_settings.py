"""Test settings: a throwaway local Postgres, never AWS. Env defaults are set BEFORE importing settings."""
import os

for k, v in {
    "MC_SECRET_KEY": "test-secret-key-not-used-anywhere-else",
    "MC_DEBUG": "0",
    "MC_DB_PORT": "54329",
    "MC_DB_SSLMODE": "prefer",
    "MC_CONSOLE_HOST": "console.test",
    "MC_MAILVIEW_HOST": "mailview.test",
    "MC_EXTRA_HOSTS": "testserver",
    "MC_SSL_REDIRECT": "0",
    "MC_EXPECTED_SNS_TOPIC_ARNS": "arn:aws:sns:ap-south-1:111122223333:mc-ses-events",
    "MC_WEBAUTHN_ORIGIN": "https://console.test",
}.items():
    os.environ.setdefault(k, v)

from .settings import *  # noqa: E402,F401,F403

SESSION_COOKIE_NAME = "mcsession"  # __Host- prefix requires Secure; tests use plain HTTP
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
STORAGES = {**STORAGES, "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}}
