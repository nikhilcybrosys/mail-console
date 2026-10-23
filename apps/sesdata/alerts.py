"""Alert evaluation and delivery.

`evaluate` opens and resolves alerts from the data already in our database (deduped by key, resolved automatically).
`notify_pending` pushes them to the configured channels (see channels.py): once per alert, per channel, with a retry
for a channel that failed, a "resolved" notice, and quiet hours that hold back warnings (never urgent alerts).
"""
import hashlib
import logging
from datetime import timedelta

import requests
from django.conf import settings
from django.utils import timezone

from . import channels, metrics
from .models import AccountSnapshot, Alert, DnsCheckResult

log = logging.getLogger(__name__)
MIN_SAMPLE = 200  # kept for callers that import it; the live value is settings.ALERT_MIN_SAMPLE


def _set(key, severity, title, detail, active):
    open_ = Alert.objects.filter(key=key, resolved_at__isnull=True).first()
    if active and open_ is None:
        return Alert.objects.create(key=key, severity=severity, title=title, detail=detail)
    if active and open_ and open_.severity != severity:
        open_.severity, open_.title, open_.detail = severity, title, detail
        open_.notified_at, open_.notified_channels, open_.resolved_notified_at = None, [], None  # escalate: notify again
        open_.save()
    elif not active and open_:
        open_.resolved_at = timezone.now()
        open_.save(update_fields=["resolved_at"])
    return open_


def _dur(td):
    minutes = int(td.total_seconds() // 60)
    return f"{minutes // 60} hours" if minutes >= 120 and minutes % 60 == 0 else f"{minutes} min" if minutes < 120 else f"{minutes / 60:.1f} hours"


def silent_threshold(config_set, last_event_at):
    """How long a config set may go without an event before that is unusual. None = too little history to judge.

    At least ALERT_SILENT_MIN_MINUTES, and at least GAP_FACTOR times the usual gap between sends (so mail sent a few
    times a day is not "silent" between mails), capped at ALERT_SILENT_MAX_HOURS. "Usual" is measured over the 7 days
    ENDING AT THE LAST EVENT, not ending now: a long silence must not shrink its own baseline and excuse itself.
    """
    n = metrics.send_count(config_set, 7, last_event_at)
    if n < 3:
        return None
    floor = timedelta(minutes=settings.ALERT_SILENT_MIN_MINUTES)
    cap = max(timedelta(hours=settings.ALERT_SILENT_MAX_HOURS), floor)
    return min(max((timedelta(days=7) / n) * settings.ALERT_SILENT_GAP_FACTOR, floor), cap)


def _resolve_missing(prefixes, active_keys):
    """Alerts keyed per sender app resolve when the app drops out of the window altogether."""
    for a in Alert.objects.filter(resolved_at__isnull=True):
        if a.key.startswith(prefixes) and a.key not in active_keys:  # str.startswith takes a tuple; the ORM lookup does not
            a.resolved_at = timezone.now()
            a.save(update_fields=["resolved_at"])


def evaluate(now=None, silent_minutes=None):
    now = now or timezone.now()
    t = settings.ALERT_THRESHOLDS
    rep = metrics.reputation_estimate(24, now)
    big = rep["sample"] >= settings.ALERT_MIN_SAMPLE
    kinds = (("bounce", t["bounce_warn"], t["bounce_page"], "Bounce"), ("complaint", t["complaint_warn"], t["complaint_page"], "Complaint"))
    for kind, warn, page, label in kinds:
        rate = rep[f"{kind}_rate"]
        sev = "page" if big and rate >= page else "warn"
        _set(f"{kind}_rate", sev, f"{label} rate {rate:.2%} (estimate, 24h)", f"{rep['sample']} sends in 24h. Authoritative value: CloudWatch Reputation.{label}Rate.", big and rate >= warn)

    # The same thresholds per sender app, so one misbehaving app is named instead of hiding in the account-wide average.
    active = set()
    for app, r in metrics.reputation_by_app(24, now).items():
        enough = r["sample"] >= settings.ALERT_APP_MIN_SAMPLE
        for kind, warn, page, label in kinds:
            rate = r[f"{kind}_rate"]
            key = f"app_{kind}:{app[:50]}:{hashlib.sha1(app.encode()).hexdigest()[:8]}"
            on = enough and rate >= warn
            if on:
                active.add(key)
            _set(key, "page" if rate >= page else "warn", f"{label} rate {rate:.2%} for app {app} (estimate, 24h)",
                 f"{r['sample']} sends from this app in 24h ({r['bounces'] if kind == 'bounce' else r['complaints']} {kind}s). Look at its recipients and list hygiene.", on)
    _resolve_missing(("app_bounce:", "app_complaint:"), active)

    for snap in {s.region: s for s in AccountSnapshot.objects.order_by("taken_at")}.values():  # latest per region
        r = snap.region
        _set(f"enforcement:{r}", "page", f"SES enforcement status {snap.enforcement_status} in {r}", "Account is under review or paused by AWS.", snap.enforcement_status not in ("HEALTHY", ""))
        _set(f"sending_disabled:{r}", "page", f"SES sending is DISABLED in {r}", "Account-level sending is off.", not snap.sending_enabled)
        pct = snap.sent_last_24h / snap.max_24h_send if snap.max_24h_send else 0
        _set(f"quota:{r}", "warn", f"Daily quota {pct:.0%} used in {r}", f"{snap.sent_last_24h:.0f} of {snap.max_24h_send:.0f}", pct >= t["quota_warn"])

    last = {k: v for k, v in metrics.last_event_by_config_set().items() if v}
    for cs, ts in last.items():
        limit = timedelta(minutes=silent_minutes) if silent_minutes is not None else silent_threshold(cs, ts)
        if limit is None:
            _set(f"silent:{cs}", "warn", "", "", False)  # too little history to say what normal is: resolve, do not alert
            continue
        _set(f"silent:{cs}", "warn", f"No SES events for config set {cs or '(none)'} in {_dur(limit)}+",
             "Pipeline stalled or senders stopped. Usual gap between sends is much shorter than this.", (now - ts) > limit)

    from apps.inbound import dmarcstats  # imported here: inbound must not be needed to import this module
    col = dmarcstats.collection(settings.DMARC_ENABLED, now)
    _set("dmarc_silent", "warn", "No DMARC reports received by mail for 3+ days",
         "Reports normally arrive daily. Check the reports address's MX record, the SES receipt rule and the DMARC worker. (Only raised once reports have arrived before.)",
         bool(col and col["silent"]))

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


def notify_pending(post=requests.post, now=None):
    """Deliver notices. Returns how many alerts now have their "firing" notice on every configured channel."""
    now = now or timezone.now()
    chans = channels.configured()
    if not chans:
        return 0
    quiet = channels.in_quiet_hours(now)
    sent = 0
    for a in Alert.objects.filter(resolved_at__isnull=True, notified_at__isnull=True):
        if quiet and a.severity != "page":
            continue  # a warning can wait for the end of quiet hours; an urgent alert cannot
        done = set(a.notified_channels or [])
        for ch in chans:
            if ch in done:
                continue
            try:
                channels.send(ch, "alert.firing", a, post)
            except Exception as exc:  # noqa: BLE001: log the kind of failure only (the message could contain the URL)
                log.warning("%s notify failed for alert %s: %s", ch, a.pk, type(exc).__name__)
                continue
            done.add(ch)
        a.notified_channels = sorted(done)
        if set(chans) <= done:
            a.notified_at = now
            sent += 1
        a.save(update_fields=["notified_channels", "notified_at"])
    if settings.ALERT_NOTIFY_RESOLVED:
        for a in Alert.objects.filter(resolved_at__isnull=False, notified_at__isnull=False, resolved_notified_at__isnull=True,
                                      resolved_at__gte=now - timedelta(days=1)):
            if quiet and a.severity != "page":
                continue
            ok = True
            for ch in chans:
                try:
                    channels.send(ch, "alert.resolved", a, post)
                except Exception as exc:  # noqa: BLE001
                    ok = False
                    log.warning("%s resolved-notice failed for alert %s: %s", ch, a.pk, type(exc).__name__)
            if ok:
                a.resolved_notified_at = now
                a.save(update_fields=["resolved_notified_at"])
    return sent
