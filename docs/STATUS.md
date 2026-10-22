# Project status

Legend: **verified** = exercised against a real AWS account (one production account) or a real browser, not only fakes.
**tested** = covered by automated tests against a real local PostgreSQL. **not yet exercised** = built and tested, but
never run for real.

## What works
- **Event pipeline (verified):** SES publishes to an SNS topic, an SQS queue (with a dead-letter queue) feeds a worker that
  parses events idempotently with an order-independent delivery state machine, a fail-closed topic allow-list and
  plain-English bounce explanations. Real events from a real account flow end to end. Running it against real AWS found three
  bugs the fakes hid (SNS signature version 1, datetimes in snapshots, SES's plain-text validation notice); all are fixed.
- **Monitoring (verified):** account health, quota, suppression-list mirror, DNS checks for DKIM, SPF, DMARC and MAIL FROM,
  reputation estimates (the console's own; CloudWatch is authoritative), bounce and complaint breakdowns by sender app and by
  recipient provider.
- **Alerts (tested):** per-app and account-wide rates, a "no events" alert whose wait scales with how often you send, Slack and
  a signed generic webhook with per-channel retry, resolved notices and quiet hours. Delivery to a real Slack or webhook
  endpoint is **not yet exercised**.
- **Setup check (verified):** one page that says whether the console is wired up end to end and what to do if not, including a
  passkey-gated test that assumes each AWS role once.
- **Sign-in (verified):** OpenID Connect against a real provider; accounts are bound to the provider's issuer and subject;
  strict `email_verified`; the app refuses to start without a domain policy.
- **Passkeys (verified in a real browser):** registration, step-up and assertion with a virtual authenticator.
- **Safety (tested):** role-based access; a four-eyes approval flow for risky changes; short-lived write roles tagged with the
  acting person; a hash-chained append-only audit log enforced by a database trigger.
- **Exports and saved views (verified in a real browser):** CSV export of sent mail and the suppression list (capability, fresh
  passkey, audit row, row cap, formula-injection defence), private saved views.
- **Prometheus `/metrics` (verified with the official parser):** off unless a token is set; aggregate numbers only.
- **Compose (opt-in):** one-off mail from addresses you list, through a separate AWS role that can only call `SendEmail`.
  Role assumption is verified against real AWS (positive and negative cases). **The actual `SendEmail` call has not yet been
  made against real SES**: it is tested with a stand-in, and the IAM policy with the policy simulator.
- **Inbound (tested):** HTML sanitizer, secret redaction, a cookie-less renderer on a separate origin, a DMARC report parser,
  attachment downloads gated on a clean malware scan. The code that fills the inbox from a Mail Manager archive is **not
  built**, so the inbox is empty until it exists.
- **Interface:** server-rendered Django and HTMX, light and dark themes, two densities, a command palette, a detail drawer and
  keyboard navigation, checked by a CSP and design-system lint, a WCAG AA contrast test, and real-browser runs.
- **AWS setup:** plain AWS CLI steps and IAM policy files in `aws/`, validated by IAM Access Analyzer. Applying them to a real
  account found a serious bug the policy simulator had hidden: AWS does not supply `sts:ExternalId` when it checks
  `sts:SetSourceIdentity`, so the original trust policies could never be assumed. Fixed and documented in `aws/README.md`.
  The roles in `aws/` that existed before Compose cannot send mail; Compose's send role is the only, documented exception.

## Known gaps
- Write actions through the approval flow (suppression changes, identity and event-destination changes) have been tested and
  the roles proven assumable, but a real change through them has **not yet been made** on a real account.
- Mail Manager archive sync and an inbox fed by it; reply threading. Customer replies are best handled where the tickets live.
- Bulk suppression imports, template editing, break-glass access.
- Event table is not partitioned (fine for tens of millions of rows; see `docs/DEVIATIONS.md`).
- No off-site backup helper in the repo (the nightly dump script is deployment-specific).
- CI (GitHub Actions) runs tests on PostgreSQL 16 (including the AWS policy tests), Django deployment checks, a migrations
  check, a dependency vulnerability and licence audit, and a Docker build with a smoke test of the demo. `/healthz/` and the
  worker heartbeat file exist for health checks.

## Repository
Public under Apache-2.0. GitHub settings in place: private vulnerability reporting (what `SECURITY.md` points to), secret
scanning with push protection, Dependabot alerts and security updates, and `main` protected (the CI jobs must pass, branches
must be up to date, no force-pushes or deletions).

Still open:
- Decide whether to move to Django 6 or stay on 5.2 LTS (major Django bumps are ignored in `.github/dependabot.yml`).
- Have the licence and copyright holder wording reviewed.
