# Mail Console

Secure internal console for Amazon SES: sent-mail log with event timelines, suppression management,
identity/DNS health, alerts, approvals and a tamper-evident audit log. Django 5.2 + HTMX, PostgreSQL 16.
Project status and known gaps: `docs/STATUS.md`.

## Try it (demo with synthetic data)
    docker compose up --build
    # then open http://localhost:8000/dev-login/?email=admin@example.com

This starts the console and PostgreSQL with made-up mail data. It runs in a development mode with a sign-in shortcut
and is bound to `127.0.0.1`: it is for looking around, never for a real deployment (see `SECURITY.md`).

## Connect it to your AWS account
`aws/README.md` has the few CLI commands and the IAM policy files you need: an SNS topic and SQS queue that receive SES
events, and three roles (read-only, plus two narrow write roles) that can never send mail. There is no hosting stack to
apply: run the container on any small server. This has not yet been run against a real AWS account.

## Local development
    python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
    # throwaway Postgres on :54329 (see config/test_settings.py), then:
    .venv/bin/python -m pytest

Run locally (DEBUG only; dev login is refused unless DEBUG is on):
    MC_DEBUG=1 MC_DEV_LOGIN=1 MC_SECRET_KEY=dev MC_DB_PORT=54329 .venv/bin/python manage.py runserver
    manage.py create_console_user you@example.com --role security_admin

Never `source` env files; configuration comes from environment variables (`config/settings.py`, prefix `MC_`).

## Components
- `apps/sesdata`: events parser, state machine, ingest worker, SES sync, DNS checks, metrics, alerts, AWS facade
- `apps/approvals`: four-eyes workflow; `apps/audit`: hash-chained audit log; `apps/accounts`: SSO, passkeys, sessions
- `apps/inbound`: MIME parsing, sanitizer, redaction, mailview renderer; `apps/console`: pages
- `aws/`: the AWS setup as CLI steps and IAM policy files (`aws/README.md`); `scripts/phase0_audit.py`: read-only AWS audit

## Sign-in
Any OpenID Connect provider with a discovery URL works (Google, Okta, Microsoft Entra, Keycloak, Authentik...):
`MC_OIDC_DISCOVERY_URL`, `MC_OIDC_CLIENT_ID`, `MC_OIDC_CLIENT_SECRET`, `MC_OIDC_PROVIDER_NAME` (button label).

- **Domain policy is required.** Set `MC_OIDC_ALLOWED_DOMAIN` to your organisation's e-mail domain (with Google the `hd`
  claim must match too), or set `MC_OIDC_ALLOW_ANY_DOMAIN=1` to accept any verified address on purpose. Without one of
  them the app refuses to start in production.
- **People must be provisioned** with `manage.py create_console_user`. The e-mail only selects the account: the first
  sign-in binds the provider's stable issuer and subject to it, and every later sign-in must present the same pair, or it
  is refused and audited (`login.identity_mismatch`). Have each person sign in soon after you add them, and reset a
  binding with `create_console_user --reset-identity`.
- **Strict claims.** `email_verified` must be true. Microsoft Entra does not send it by default, so sign-in fails closed
  until you configure it. Use a tenant-specific discovery URL: multi-tenant endpoints (templated issuer) are refused.
- Changes to SES additionally ask for a passkey.

## License
Licensed under the [Apache License 2.0](LICENSE). Third-party components are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The name, logo and accent colour are configurable with the
`MC_BRAND_*` settings. Contributions are accepted under the same licence with a DCO sign-off (see
[CONTRIBUTING.md](CONTRIBUTING.md)).
