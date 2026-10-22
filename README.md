# Mail Console

A secure management and monitoring console for Amazon SES. See what happened to every email, fix deliverability
problems, and change SES settings safely, without opening the AWS console. Django 5.2 + HTMX, PostgreSQL 16, no Node
toolchain.

<p align="center">
  <img src="docs/screenshots/overview-light.png" alt="Overview: delivery health, alerts, KPIs, delivery chart and reputation" width="49%">
  <img src="docs/screenshots/overview-dark.png" alt="The same overview in dark mode" width="49%">
</p>

## What it does
- **Sent mail:** every message SES accepted, with its delivery timeline. Bounces come with a plain-language explanation
  and what to do next.
- **Suppression list:** search it, remove a single address with a passkey check, or remove many through an approval.
- **Domains and DNS:** each sending identity next to the DKIM, SPF and DMARC records it needs, expected against found.
- **Alerts:** DNS problems, enforcement or sending paused, and no events arriving.
- **Safe changes:** every change to SES asks for a passkey, and risky ones (bulk suppression removal, pausing sending,
  identity and event-destination changes) also need a second person to approve. Changes run with narrowly scoped AWS
  roles that can never send mail.
- **Tamper-evident audit log:** every sign-in, change and message-body view, hash-chained so edits show.

<p align="center">
  <img src="docs/screenshots/message-drawer.png" alt="Sent mail list with a message's timeline and bounce explanation open in a side drawer" width="49%">
  <img src="docs/screenshots/domains-and-dns.png" alt="Domains and DNS: DKIM, SPF and DMARC checks with expected and found values" width="49%">
</p>
<p align="center">
  <img src="docs/screenshots/approvals.png" alt="Approvals: a second person must approve risky changes" width="49%">
  <img src="docs/screenshots/audit-log-dark.png" alt="Audit log with hash-chain verification" width="49%">
</p>

The screenshots use synthetic demo data. Project status and known gaps: [docs/STATUS.md](docs/STATUS.md).

## Try it (demo with synthetic data)
    docker compose up --build
    # then open http://localhost:8000/dev-login/?email=admin@example.com

This starts the console and PostgreSQL with made-up mail data. It runs in a development mode with a sign-in shortcut
and is bound to `127.0.0.1`: it is for looking around, never for a real deployment (see `SECURITY.md`).

## Connect it to your AWS account
`aws/README.md` has the few CLI commands and the IAM policy files you need: an SNS topic and SQS queue that receive SES
events, and three roles (read-only, plus two narrow write roles) that can never send mail. There is no hosting stack to
apply: run the container on any small server. The steps have been applied to a real production account and checked there.

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

## Alerts
Alerts always appear on the Alerts page. To get them elsewhere, set a channel (https only):

| Setting | Meaning |
|---|---|
| `MC_ALERT_SLACK_WEBHOOK_URL` | a Slack incoming webhook |
| `MC_ALERT_WEBHOOK_URL`, `MC_ALERT_WEBHOOK_SECRET` | any tool that accepts a JSON `POST`; the secret is optional and signs each request |
| `MC_ALERT_QUIET_HOURS`, `MC_ALERT_QUIET_TZ` | for example `22:00-07:00` and `Asia/Kolkata`: warnings wait until the window ends, urgent alerts never do |
| `MC_ALERT_NOTIFY_RESOLVED` | send a notice when an alert resolves (default on) |

What opens an alert (all values are fractions; the Alerts page shows what is in force):

| Setting | Default | Meaning |
|---|---|---|
| `MC_ALERT_BOUNCE_WARN` / `_PAGE` | `0.02` / `0.04` | bounce rate warning / urgent (SES starts reviewing at about 5%) |
| `MC_ALERT_COMPLAINT_WARN` / `_PAGE` | `0.0005` / `0.0008` | complaint rate (SES starts reviewing at about 0.1%) |
| `MC_ALERT_MIN_SAMPLE`, `MC_ALERT_APP_MIN_SAMPLE` | `200`, `50` | sends in 24 hours needed before a rate alerts, account-wide and per sender app |
| `MC_ALERT_QUOTA_WARN` | `0.80` | share of the daily quota used |
| `MC_ALERT_SILENT_MIN_MINUTES`, `_GAP_FACTOR`, `_MAX_HOURS` | `60`, `3`, `24` | "no events" waits at least the minimum, and at least the factor times the usual gap between sends, capped |

Bounce and complaint rates are also checked per sender app (the `mc-app` tag on your messages), so one app with a bad
list is named instead of hiding in the account average. A config set with fewer than 3 sends in a week is never reported silent.

**Verifying the webhook.** With a secret set, each request has `X-Mail-Console-Timestamp` (unix seconds) and
`X-Mail-Console-Signature: sha256=<hex>`, the HMAC-SHA256 of `"<timestamp>." + raw body` keyed with the secret:

    import hashlib, hmac, time
    def valid(secret: bytes, body: bytes, ts: str, sig: str) -> bool:
        good = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(good, sig) and abs(time.time() - int(ts)) < 300   # also rejects replays

The body is `{"event": "alert.firing" | "alert.resolved" | "test", "alert": {id, key, severity, title, detail, opened_at, resolved_at}, ...}`.
The Alerts page has a button that sends a test notification to every channel.

## License
Licensed under the [Apache License 2.0](LICENSE). Third-party components are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The name, logo and accent colour are configurable with the
`MC_BRAND_*` settings. Contributions are accepted under the same licence with a DCO sign-off (see
[CONTRIBUTING.md](CONTRIBUTING.md)).
