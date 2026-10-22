"""What /metrics reports: aggregate numbers only, read from our own database (no AWS calls).

Deliberately NOT here: recipient addresses or domains, subjects, message ids. Every label is a small, bounded set
(event type, region, severity, sender app capped at TOP_APPS), so a scrape cannot leak personal data or blow up a
time-series database's cardinality.

Windowed numbers are gauges over the last 24 hours (cheap indexed range queries). Rates are the console's own
ESTIMATE, labelled as such; CloudWatch Reputation.* is the authoritative value.
"""
from datetime import timedelta

from django.db.models import Count, Max
from django.utils import timezone

from apps.core.prom import Family

TOP_APPS = 50


def collect(now=None):
    from apps.approvals.models import ApprovalRequest

    from . import metrics
    from .models import AccountSnapshot, Alert, MessageEvent, SuppressionEntry

    now = now or timezone.now()
    since = now - timedelta(hours=24)
    fams = []

    ev = Family("mailconsole_events_24h", "SES events received in the last 24 hours, by event type.")
    for r in MessageEvent.objects.filter(event_ts__gte=since).values("event_type").annotate(n=Count("id")).order_by("event_type"):
        ev.add(r["n"], event_type=r["event_type"])
    fams.append(ev)

    rep = metrics.reputation_estimate(24, now)
    fams.append(Family("mailconsole_reputation_sample_24h", "Sends in the last 24 hours that the estimate is based on.").add(rep["sample"]))
    fams.append(Family("mailconsole_reputation_bounce_rate_24h", "Estimated permanent bounce rate over 24 hours, a fraction (not SES's own figure).").add(rep["bounce_rate"]))
    fams.append(Family("mailconsole_reputation_complaint_rate_24h", "Estimated complaint rate over 24 hours, a fraction (not SES's own figure).").add(rep["complaint_rate"]))

    # Per sender app: raw event counts, so PromQL does the arithmetic (and a rule can use any window or threshold it likes).
    # These are plain counts: unlike the estimate above they include transient bounces and suppression-driven ones.
    key = "message__source_app"
    per_app = {}
    for r in MessageEvent.objects.filter(event_ts__gte=since, event_type__in=("send", "delivery", "bounce", "complaint")) \
            .values(key, "event_type").annotate(n=Count("id")):
        per_app.setdefault(r[key] or "(untagged)", {})[r["event_type"]] = r["n"]
    top = sorted(per_app.items(), key=lambda kv: (-kv[1].get("send", 0), kv[0]))[:TOP_APPS]
    app_ev = Family("mailconsole_app_events_24h", f"SES events in the last 24 hours by sender app and event type (top {TOP_APPS} apps by sends).")
    for app, counts in top:
        for event_type in ("send", "delivery", "bounce", "complaint"):
            app_ev.add(counts.get(event_type, 0), app=app, event_type=event_type)
    fams.append(app_ev)

    last = MessageEvent.objects.aggregate(t=Max("event_ts"))["t"]
    fams.append(Family("mailconsole_last_event_timestamp_seconds", "Unix time of the newest SES event the console has stored.").add(last.timestamp() if last else 0))

    # Latest account snapshot per region (one row each; the table grows by one row per region every sync).
    snaps = AccountSnapshot.objects.order_by("region", "-taken_at").distinct("region")
    spec = (("mailconsole_ses_sending_enabled", "1 if SES sending is enabled for the account in this region.", lambda s: s.sending_enabled),
            ("mailconsole_ses_production_access", "1 if the account is out of the SES sandbox in this region.", lambda s: s.production_access),
            ("mailconsole_ses_enforcement_healthy", "1 if SES reports the account as healthy (not under review or paused).", lambda s: s.enforcement_status in ("HEALTHY", "")),
            ("mailconsole_ses_sent_24h", "Emails SES counted against the daily quota in the last 24 hours.", lambda s: s.sent_last_24h),
            ("mailconsole_ses_max_24h_send", "The account's daily sending quota.", lambda s: s.max_24h_send),
            ("mailconsole_ses_quota_used_ratio", "Share of the daily quota used, 0 to 1.", lambda s: (s.sent_last_24h / s.max_24h_send) if s.max_24h_send else 0.0),
            ("mailconsole_last_sync_timestamp_seconds", "Unix time of the last successful SES state sync.", lambda s: s.taken_at.timestamp()))
    rows = list(snaps)
    for name, text, fn in spec:
        fam = Family(name, text)
        for s in rows:
            fam.add(fn(s), region=s.region)
        fams.append(fam)

    sup = Family("mailconsole_suppression_entries", "Addresses on the account suppression list, by region.")
    for r in SuppressionEntry.objects.values("region").annotate(n=Count("id")).order_by("region"):
        sup.add(r["n"], region=r["region"])
    fams.append(sup)

    open_by = {r["severity"]: r["n"] for r in Alert.objects.filter(resolved_at__isnull=True).values("severity").annotate(n=Count("id"))}
    al = Family("mailconsole_alerts_open", "Open alerts, by severity (warn or page).")
    for sev in ("warn", "page"):
        al.add(open_by.get(sev, 0), severity=sev)
    fams.append(al)

    fams.append(Family("mailconsole_approvals_pending", "Changes waiting for a second person to approve.")
                .add(ApprovalRequest.objects.filter(state=ApprovalRequest.PENDING).count()))
    return fams
