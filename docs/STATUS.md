# Project status

Legend: **done** = built and covered by automated tests against a real local PostgreSQL. **unverified** = depends on
AWS or an identity provider behaving as documented and has only been exercised against fakes.

Nothing here has been run against a real AWS account.

## What works
- **Ingestion:** SES event publishing (SNS to SQS) parsed idempotently, with an order-independent delivery state machine,
  a fail-closed topic allow-list and plain-English bounce explanations (done; AWS side unverified).
- **Monitoring:** account health, reputation estimates, quota, suppression-list mirror, DNS checks for DKIM, SPF, DMARC
  and MAIL FROM, alert evaluation with a Slack webhook (done; AWS and DNS lookups unverified).
- **Sign-in:** any OpenID Connect provider; accounts are bound to the provider's issuer and subject on first sign-in; strict
  `email_verified` and issuer pinning; the app refuses to start without a domain policy (done; tested against a fake provider only).
- **Safety:** role-based access, a four-eyes approval flow for risky changes (self-approval, expiry, tampering and
  double execution are tested), short-lived write roles tagged with the acting person, a hash-chained append-only audit
  log enforced by a database trigger, passkey step-up for writes and body views (passkey ceremony unverified).
- **Inbound:** a sanitizer for untrusted email HTML (XSS corpus), secret redaction, a cookie-less renderer on a
  separate origin, a DMARC report parser, and attachment downloads gated on a clean malware scan (done). The code that
  fills the inbox from a Mail Manager archive is **not built**, so the inbox is empty until it exists.
- **Interface:** server-rendered Django and HTMX with a token-based design system, light and dark themes, two
  densities, a command palette, a detail drawer and keyboard navigation. Every screen is covered by a lint for CSP and
  design-system rules, a WCAG AA contrast test, and a real-browser run (zero CSP violations, zero axe findings).
- **Infrastructure as code:** Terraform for the whole stack. `terraform fmt` and `validate` pass; it has **never been
  planned or applied**, so IAM, KMS and policy correctness is unproven (`infra/README.md` lists known gaps).

## Known gaps
- Mail Manager archive sync and an inbox fed by it; scan-result ingestion that sets attachment `scan_state`.
- Bulk suppression imports, template editing, break-glass access, per-user rate limits.
- The filter bar has removable chips but no "add filter" menu; no saved views; no CSV export.
- Event table is not partitioned (fine for tens of millions of rows; see `docs/DEVIATIONS.md`).
- Sign-in and passkeys have not been exercised against a real provider or authenticator.
- The CI workflow passes actionlint and GitHub's workflow schema; `compose.yaml` and the Dependabot file pass their official
  schemas. The `Dockerfile` was reviewed by hand against hadolint's rules (the real linter runs in CI). None of the container
  files has been **built or run** by the author (no container runtime was used). The CI workflow builds and smoke-tests them, so the first CI run is
  their first real test. The Terraform has no image registry or deployment pipeline yet; environment names match the app
  (checked), and `/healthz/` and the worker heartbeat file exist, but nothing has been deployed.
- No external security review or penetration test has been done.

## Before publishing the repository
- Push, then enable GitHub private vulnerability reporting (`SECURITY.md` points to it) and branch protection that
  requires the CI jobs.
- Watch the first CI run: the Docker build and demo smoke test have not been executed anywhere yet.
- Have the licence and copyright holder reviewed.
