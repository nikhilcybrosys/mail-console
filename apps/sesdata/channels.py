"""Where alerts go besides the console: Slack, and a generic webhook any tool can receive. Plus quiet hours.

Delivery is never email through the same SES account (circular: the alert about SES would depend on SES).
Both channels are https only (checked at start-up), never follow redirects, and send only the alert text the console
already shows: no message bodies and no secrets.

Generic webhook: JSON body; if MC_ALERT_WEBHOOK_SECRET is set, each request carries
    X-Mail-Console-Timestamp: <unix seconds>
    X-Mail-Console-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>." + raw body, keyed with the secret>
so the receiver can check who sent it and reject replays.
"""
import hashlib
import hmac
import json
import re
import time
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from django.conf import settings
from django.utils import timezone

SLACK, WEBHOOK = "slack", "webhook"
LABELS = {SLACK: "Slack", WEBHOOK: "Webhook"}


class DeliveryError(Exception):
    """The receiver did not answer with a 2xx (redirects are not followed, so a 3xx lands here too)."""


def _check(response):
    response.raise_for_status()  # 4xx and 5xx
    code = getattr(response, "status_code", 200)
    if not 200 <= code < 300:
        raise DeliveryError(f"HTTP {code}")


def configured():
    return [c for c, url in ((SLACK, settings.ALERT_SLACK_WEBHOOK_URL), (WEBHOOK, settings.ALERT_WEBHOOK_URL)) if url]


def quiet_window():
    """(start_minutes, end_minutes) after midnight in the configured zone, or None when quiet hours are off."""
    m = re.fullmatch(r"(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})", settings.ALERT_QUIET_HOURS.strip())
    if not m:
        return None
    start, end = int(m[1]) * 60 + int(m[2]), int(m[3]) * 60 + int(m[4])
    return None if start == end else (start, end)


def in_quiet_hours(now=None):
    w = quiet_window()
    if w is None:
        return False
    local = (now or timezone.now()).astimezone(ZoneInfo(settings.ALERT_QUIET_TZ))
    minute = local.hour * 60 + local.minute
    start, end = w
    return start <= minute < end if start < end else (minute >= start or minute < end)


def _slack_escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")  # Slack's only three special characters


def _console_url():
    return f"https://{settings.CONSOLE_HOST}/alerts/"


def slack_body(event, alert):
    if event == "alert.resolved":
        text = f":white_check_mark: *{_slack_escape(settings.BRAND_NAME)}* Resolved: {_slack_escape(alert.title)}"
    elif event == "test":
        text = f":bell: *{_slack_escape(settings.BRAND_NAME)}* Test notification: this channel is working."
    else:
        icon = ":rotating_light:" if alert.severity == "page" else ":warning:"
        text = f"{icon} *{_slack_escape(settings.BRAND_NAME)}* {_slack_escape(alert.title)}\n{_slack_escape(alert.detail)}"
    return {"text": text}


def webhook_body(event, alert):
    def iso(v):
        return v.isoformat() if v else None
    return {"event": event, "source": "mail-console", "sent_at": iso(timezone.now()), "url": _console_url(),
            "alert": {"id": getattr(alert, "pk", None), "key": alert.key, "severity": alert.severity, "title": alert.title,
                      "detail": alert.detail, "opened_at": iso(getattr(alert, "opened_at", None)),
                      "resolved_at": iso(getattr(alert, "resolved_at", None))}}


def sign(secret, timestamp, payload):
    return "sha256=" + hmac.new(secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()


def send(channel, event, alert, post):
    """Deliver one notice. Raises on any failure; the caller records which channels succeeded."""
    if channel == SLACK:
        r = post(settings.ALERT_SLACK_WEBHOOK_URL, json=slack_body(event, alert), timeout=5, allow_redirects=False)
    elif channel == WEBHOOK:
        payload = json.dumps(webhook_body(event, alert), separators=(",", ":"), sort_keys=True).encode()
        headers = {"Content-Type": "application/json"}
        if settings.ALERT_WEBHOOK_SECRET:
            ts = str(int(time.time()))
            headers.update({"X-Mail-Console-Timestamp": ts, "X-Mail-Console-Signature": sign(settings.ALERT_WEBHOOK_SECRET, ts, payload)})
        r = post(settings.ALERT_WEBHOOK_URL, data=payload, headers=headers, timeout=5, allow_redirects=False)
    else:
        raise ValueError(f"unknown channel {channel!r}")
    _check(r)


def send_test(post):
    """Send a test notice to every configured channel. Returns [(channel, ok, short reason)]; never raises."""
    fake = SimpleNamespace(pk=None, key="test", severity="warn", title="Test notification", detail="Sent from the Alerts page.",
                           opened_at=timezone.now(), resolved_at=None)
    out = []
    for ch in configured():
        try:
            send(ch, "test", fake, post)
            out.append((ch, True, ""))
        except Exception as exc:  # noqa: BLE001: report the kind of failure, not the URL or response text
            resp = getattr(exc, "response", None)
            reason = str(exc) if isinstance(exc, DeliveryError) else f"HTTP {resp.status_code}" if resp is not None else exc.__class__.__name__
            out.append((ch, False, reason))
    return out
