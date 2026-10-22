# Deviations from the approved plan

1. **No monthly partitioning of `message_event`.** Django has no declarative partitioning; v1 relies on indexes. Revisit (pg_partman or raw-SQL partitioned table) before ~50M rows.
2. **No raw (unredacted) body reveal.** Plan allowed a permissioned raw reveal. v1 only shows the redacted, sanitized view; raw reveal needs its own design (break-glass + second approver).
3. **Links in email are inert text** (URL shown with tokens redacted), and **remote images are dropped with no proxy**. Stricter than planned; a safe image proxy is deferred.
4. **mailview tokens are time-limited (60 s) but not single-use.** A leaked URL is usable for up to a minute by anyone, but only for content the issuer was allowed to view. Single-use needs shared state (DB row) and was skipped.
5. **No Celery.** Two management commands (`ingest_ses_events`, `sync_ses_state`) run as ECS tasks.
6. **Passkey step-up uses a session timestamp (10 min window)**, not a per-action challenge. A per-action assertion would be stricter.
7. **Alert evaluation does not check DLQ depth or oldest-message age** in the app; those belong to CloudWatch alarms in Terraform.
8. **Python 3.12 / Django 5.2 / psycopg 3 / authlib / fido2 2.x** chosen; fido2's API changed in 2.x, so do not downgrade.
