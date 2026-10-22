"""Alert evaluation. Dedupes by key, resolves automatically, notifies Slack once per open alert.

Delivery is NOT email through the same SES account (circular): Slack webhook only (PagerDuty/SNS later).
"""
import logging
from datetime import timedelta

import requests
from django.conf import settings
from django.utils import timezone

from . import metrics
from .models import AccountSnapshot, Alert, DnsCheckResult

log = logging.getLogger(__name__)
MIN_SAMPLE = 200  # do not alert on rates from tiny volumes


def _set(key, severity, title, detail, active):
    open_ = Alert.objects.filter(key=key, resolved_at__isnull=True).first()
    if active and open_ is None:
        return Alert.objects.create(key=key, severity=severity, title=title, detail=detail)
    if active and open_ and open_.severity != severity:
        open_.severity, open_.title, open_.detail, open_.notified_at = severity, title, detail, None  # escalate: notify again
        open_.save()
    elif not active and open_:
        open_.resolved_at = timezone.now()
        open_.save(update_fields=["resolved_at"])
    return open_


def evaluate(now=None, silent_minutes=60):
    now = now or timezone.now()
    t = settings.ALERT_THRESHOLDS
    rep = metrics.reputation_estimate(24, now)
    big = rep["sample"] >= MIN_SAMPLE
    for kind, warn, page, label in (("bounce", t["bounce_warn"], t["bounce_page"], "Bounce"), ("complaint", t["complaint_warn"], t["complaint_page"], "Complaint")):
        rate = rep[f"{kind}_rate"]
        sev = "page" if big and rate >= page else "warn"
        _set(f"{kind}_rate", sev, f"{label} rate {rate:.2%} (estimate, 24h)", f"{rep['sample']} sends in 24h. Authoritative value: CloudWatch Reputation.{label}Rate.", big and rate >= warn)

    for snap in {s.region: s for s in AccountSnapshot.objects.order_by("taken_at")}.values():  # latest per region
        r = snap.region
        _set(f"enforcement:{r}", "page", f"SES enforcement status {snap.enforcement_status} in {r}", "Account is under review or paused by AWS.", snap.enforcement_status not in ("HEALTHY", ""))
        _set(f"sending_disabled:{r}", "page", f"SES sending is DISABLED in {r}", "Account-level sending is off.", not snap.sending_enabled)
        pct = snap.sent_last_24h / snap.max_24h_send if snap.max_24h_send else 0
        _set(f"quota:{r}", "warn", f"Daily quota {pct:.0%} used in {r}", f"{snap.sent_last_24h:.0f} of {snap.max_24h_send:.0f}", pct >= t["quota_warn"])

    last = {k: v for k, v in metrics.last_event_by_config_set().items() if v}
    for cs, ts in last.items():
        silent = (now - ts) > timedelta(minutes=silent_minutes)
        recent_volume = metrics.Message.objects.filter(config_set=cs, sent_at__gte=now - timedelta(hours=24)).exists()
        _set(f"silent:{cs}", "warn", f"No SES events for config set {cs or '(none)'} in {silent_minutes}+ min", "Pipeline stalled or senders stopped.", silent and recent_volume)

    latest = {}
    for r in DnsCheckResult.objects.order_by("checked_at"):
        latest[(r.domain, r.record_kind, tuple(r.expected))] = r
    groups = {}
    for r in latest.values():
        groups.setdefault((r.domain, r.record_kind), []).append(r)
    bad = 0
    for (domain, kind), rows in groups.items():
        failing = [r for r in rows if not r.ok]
        bad += len(failing)
        _set(f"dns:{domain}:{kind}", "warn", f"DNS {kind.upper()} problem for {domain}",
             "; ".join(r.detail for r in failing if r.detail)[:500], bool(failing))
    return {"dns_bad": bad, "open": Alert.objects.filter(resolved_at__isnull=True).count()}


def notify_pending(post=requests.post):
    """Send one Slack message per newly opened/escalated alert."""
    url = settings.ALERT_SLACK_WEBHOOK_URL
    sent = 0
    for a in Alert.objects.filter(resolved_at__isnull=True, notified_at__isnull=True):
        if not url:
            break
        icon = ":rotating_light:" if a.severity == "page" else ":warning:"
        try:
            r = post(url, json={"text": f"{icon} *Mail Console* {a.title}\n{a.detail}"}, timeout=5)
            r.raise_for_status()
        except Exception as exc:
            log.warning("slack notify failed for alert %s: %s", a.pk, type(exc).__name__)
            continue
        a.notified_at = timezone.now()
        a.save(update_fields=["notified_at"])
        sent += 1
    return sent
