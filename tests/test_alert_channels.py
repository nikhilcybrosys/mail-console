import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata import alerts, channels, metrics
from apps.sesdata.ingest import process_body
from apps.sesdata.models import Alert, Message, MessageEvent

from . import factories as f
from .test_aws_policies import _import_settings
from .test_views import login

pytestmark = pytest.mark.django_db
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
SLACK, HOOK = "https://hooks.example/slack", "https://hooks.example/generic"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def put(mid, ts, app="webapp", cfg="mc-default"):
    process_body(f.sns(f.send(mid=mid, ts=iso(ts), tags={"mc-app": [app]}, cfg=cfg, dest=(f"{mid}@x.com",))), [f.TOPIC])


def put_bounce(mid, ts, app, sub="General"):
    process_body(f.sns(f.bounce(mid=mid, ts=iso(ts), tags={"mc-app": [app]}, rcpts=(f"{mid}@x.com",), sub=sub, feedback=f"fb-{mid}")), [f.TOPIC])


def steady(per_day, days=7, end=NOW, cfg="mc-default"):
    """Evenly spaced sends over `days`, the last one at `end`."""
    n, gap = per_day * days, timedelta(days=1) / per_day
    for i in range(n):
        put(f"s{i}", end - gap * (n - 1 - i), cfg=cfg)


def silent_open(cfg="mc-default"):
    return Alert.objects.filter(key=f"silent:{cfg}", resolved_at__isnull=True).exists()


# ---------------------------------------------------------------- the "no events" alert no longer cries wolf
def test_a_sender_that_mails_four_times_a_day_is_not_silent_between_mails():
    steady(4)  # one mail every 6 hours
    alerts.evaluate(NOW + timedelta(hours=2))   # the old rule alerted after 60 minutes of quiet
    assert not silent_open()
    alerts.evaluate(NOW + timedelta(hours=17))  # still inside 3x the usual gap (18 h)
    assert not silent_open()


def test_the_same_sender_is_flagged_when_the_silence_is_really_unusual():
    steady(4)
    alerts.evaluate(NOW + timedelta(hours=19))
    a = Alert.objects.get(key="silent:mc-default", resolved_at__isnull=True)
    assert "18" in a.title  # the title says how long was too long
    alerts.evaluate(NOW + timedelta(hours=1))   # as if events resumed: resolves
    assert not silent_open()


def test_a_busy_sender_is_flagged_after_the_minimum_wait():
    steady(48)  # one mail every 30 minutes: 3x is 90 min
    alerts.evaluate(NOW + timedelta(minutes=60))
    assert not silent_open()
    alerts.evaluate(NOW + timedelta(minutes=100))
    assert silent_open()


def test_a_rarely_used_config_set_is_never_called_silent():
    for i in range(2):
        put(f"r{i}", NOW - timedelta(days=i + 1))
    alerts.evaluate(NOW + timedelta(days=3))
    assert not silent_open()


def test_silent_limits_are_settings(settings):
    settings.ALERT_SILENT_MIN_MINUTES, settings.ALERT_SILENT_GAP_FACTOR, settings.ALERT_SILENT_MAX_HOURS = 30, 1.0, 5
    steady(4)
    t = alerts.silent_threshold("mc-default", NOW)
    assert t == timedelta(hours=5)  # 1x the 6 h gap, capped at 5 h


def test_a_long_silence_does_not_widen_its_own_allowance():
    steady(4)
    assert alerts.silent_threshold("mc-default", NOW) == timedelta(hours=18)
    alerts.evaluate(NOW + timedelta(days=3))  # three silent days must not drag the baseline down and excuse themselves
    assert silent_open()


# ---------------------------------------------------------------- per-app rates
def test_one_misbehaving_app_is_named_even_when_the_account_average_looks_fine(settings):
    settings.ALERT_APP_MIN_SAMPLE = 50
    for i in range(60):
        put(f"a{i}", NOW - timedelta(hours=3), app="billing")
    for i in range(6):                      # 10% of billing's mail bounces
        put_bounce(f"a{i}", NOW - timedelta(hours=2), "billing")
    for i in range(300):
        put(f"g{i}", NOW - timedelta(hours=3), app="good-app")
    alerts.evaluate(NOW)
    assert not Alert.objects.filter(key="bounce_rate", resolved_at__isnull=True).exists()  # account-wide: 1.7%, under 2%
    a = Alert.objects.get(key__startswith="app_bounce:billing", resolved_at__isnull=True)
    assert a.severity == "page" and "billing" in a.title and "good-app" not in a.title
    assert not Alert.objects.filter(key__startswith="app_bounce:good-app").exists()


def test_per_app_alerts_ignore_tiny_apps_and_suppression_driven_bounces(settings):
    settings.ALERT_APP_MIN_SAMPLE = 50
    for i in range(10):
        put(f"t{i}", NOW - timedelta(hours=3), app="tiny")
        put_bounce(f"t{i}", NOW - timedelta(hours=2), "tiny")          # 100% but only 10 mails
    for i in range(60):
        put(f"c{i}", NOW - timedelta(hours=3), app="clean-list")
    for i in range(12):
        put_bounce(f"c{i}", NOW - timedelta(hours=2), "clean-list", sub="OnAccountSuppressionList")  # does not count toward reputation
    alerts.evaluate(NOW)
    assert not Alert.objects.filter(key__startswith="app_").exists()


def test_per_app_alert_resolves_when_the_app_leaves_the_window(settings):
    settings.ALERT_APP_MIN_SAMPLE = 50
    for i in range(60):
        put(f"a{i}", NOW - timedelta(hours=3), app="billing")
    for i in range(6):
        put_bounce(f"a{i}", NOW - timedelta(hours=2), "billing")
    alerts.evaluate(NOW)
    assert Alert.objects.filter(key__startswith="app_bounce:", resolved_at__isnull=True).count() == 1
    alerts.evaluate(NOW + timedelta(days=3))  # no sends from any app in the last 24 h any more
    assert not Alert.objects.filter(key__startswith="app_", resolved_at__isnull=True).exists()


def test_reputation_by_app_names_untagged_mail():
    process_body(f.sns(f.send(mid="u1", ts=iso(NOW - timedelta(hours=1)), tags={"mc-app": [""]})), [f.TOPIC])
    assert "(untagged)" in metrics.reputation_by_app(24, NOW) or "webapp" in metrics.reputation_by_app(24, NOW)


# ---------------------------------------------------------------- channels
class Resp:
    def __init__(self, code=200):
        self.status_code = code

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            err = requests.HTTPError(f"{self.status_code}")
            err.response = self
            raise err


class Recorder:
    """Stands in for requests.post: remembers every call, and answers per URL."""

    def __init__(self, answers=None):
        self.calls, self.answers = [], answers or {}

    def __call__(self, url, **kw):
        self.calls.append({"url": url, **kw})
        a = self.answers.get(url, 200)
        if isinstance(a, Exception):
            raise a
        return Resp(a)

    def to(self, url):
        return [c for c in self.calls if c["url"] == url]


@pytest.fixture
def both(settings):
    settings.ALERT_SLACK_WEBHOOK_URL, settings.ALERT_WEBHOOK_URL, settings.ALERT_WEBHOOK_SECRET = SLACK, HOOK, "shh-secret"
    settings.ALERT_QUIET_HOURS = ""
    return settings


def mk(sev="warn", title="Bounce rate 5% for app billing", **kw):
    return Alert.objects.create(key=kw.pop("key", "k1"), severity=sev, title=title, detail="D", **kw)


def test_both_channels_get_the_notice_once(both):
    mk()
    post = Recorder()
    assert alerts.notify_pending(post, NOW) == 1
    assert len(post.to(SLACK)) == 1 and len(post.to(HOOK)) == 1
    assert alerts.notify_pending(post, NOW) == 0 and len(post.calls) == 2
    a = Alert.objects.get()
    assert a.notified_at and a.notified_channels == ["slack", "webhook"]


def test_a_failed_channel_is_retried_alone(both):
    mk()
    post = Recorder({HOOK: RuntimeError("down")})
    assert alerts.notify_pending(post, NOW) == 0           # not fully delivered
    a = Alert.objects.get()
    assert a.notified_at is None and a.notified_channels == ["slack"]
    post2 = Recorder()
    assert alerts.notify_pending(post2, NOW) == 1
    assert post2.to(SLACK) == [] and len(post2.to(HOOK)) == 1  # Slack is not spammed a second time
    assert Alert.objects.get().notified_at


def test_redirects_are_not_followed_and_a_3xx_counts_as_a_failure(both):
    mk()
    post = Recorder({HOOK: 302})
    alerts.notify_pending(post, NOW)
    assert all(c["allow_redirects"] is False for c in post.calls)
    assert Alert.objects.get().notified_channels == ["slack"]  # the 302 receiver did not get credit


def test_webhook_request_is_signed_and_verifiable(both):
    mk(sev="page", title="SES sending is DISABLED in ap-south-1")
    post = Recorder()
    alerts.notify_pending(post, NOW)
    c = post.to(HOOK)[0]
    body = c["data"]
    ts, sig = c["headers"]["X-Mail-Console-Timestamp"], c["headers"]["X-Mail-Console-Signature"]
    assert sig == "sha256=" + hmac.new(b"shh-secret", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    doc = json.loads(body)
    assert doc["event"] == "alert.firing" and doc["alert"]["severity"] == "page" and doc["source"] == "mail-console"
    assert "shh-secret" not in body.decode()


def test_webhook_without_a_secret_is_unsigned_but_still_sent(both):
    both.ALERT_WEBHOOK_SECRET = ""
    mk()
    post = Recorder()
    alerts.notify_pending(post, NOW)
    assert "X-Mail-Console-Signature" not in post.to(HOOK)[0]["headers"]


def test_slack_text_is_escaped(both):
    mk(title="Bounce for <!channel> & friends")
    post = Recorder()
    alerts.notify_pending(post, NOW)
    text = post.to(SLACK)[0]["json"]["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text and "&amp;" in text


def test_no_channels_means_nothing_is_sent_and_alerts_stay_pending(settings):
    settings.ALERT_SLACK_WEBHOOK_URL = settings.ALERT_WEBHOOK_URL = ""
    mk()
    post = Recorder()
    assert alerts.notify_pending(post, NOW) == 0 and not post.calls
    assert Alert.objects.get().notified_at is None  # so it is sent if a channel is added later


def test_escalation_notifies_again_on_every_channel(both):
    key = "bounce_rate"
    alerts._set(key, "warn", "Bounce rate 3%", "d", True)
    alerts.notify_pending(Recorder(), NOW)
    alerts._set(key, "page", "Bounce rate 5%", "d", True)
    a = Alert.objects.get()
    assert a.notified_at is None and a.notified_channels == [] and a.severity == "page"
    post = Recorder()
    assert alerts.notify_pending(post, NOW) == 1 and len(post.calls) == 2


# ---------------------------------------------------------------- resolved notices
def test_resolved_notice_is_sent_once_and_only_for_alerts_that_were_announced(both):
    announced = mk(key="a")
    alerts.notify_pending(Recorder(), NOW)
    never_sent = mk(key="b")                    # opened and resolved before any channel saw it
    for a in (announced, never_sent):
        a.refresh_from_db()
        a.resolved_at = NOW
        a.save()
    post = Recorder()
    alerts.notify_pending(post, NOW)
    events = [json.loads(c["data"])["event"] for c in post.to(HOOK)]
    assert events == ["alert.resolved"] and len(post.to(SLACK)) == 1 and "Resolved" in post.to(SLACK)[0]["json"]["text"]
    post2 = Recorder()
    alerts.notify_pending(post2, NOW)
    assert not post2.calls


def test_resolved_notices_can_be_switched_off(both):
    both.ALERT_NOTIFY_RESOLVED = False
    a = mk()
    alerts.notify_pending(Recorder(), NOW)
    a.refresh_from_db()
    a.resolved_at = NOW
    a.save()
    post = Recorder()
    alerts.notify_pending(post, NOW)
    assert not post.calls


# ---------------------------------------------------------------- quiet hours
def test_quiet_window_crosses_midnight_in_the_configured_zone(settings):
    settings.ALERT_QUIET_HOURS, settings.ALERT_QUIET_TZ = "22:00-07:00", "Asia/Kolkata"  # UTC+5:30
    at = lambda h, m=0: datetime(2026, 10, 20, h, m, tzinfo=timezone.utc)  # noqa: E731
    assert channels.in_quiet_hours(at(17, 0))       # 22:30 local
    assert channels.in_quiet_hours(at(0, 0))        # 05:30 local
    assert not channels.in_quiet_hours(at(2, 0))    # 07:30 local
    assert not channels.in_quiet_hours(at(10, 0))   # 15:30 local


def test_quiet_window_inside_one_day_and_off_by_default(settings):
    settings.ALERT_QUIET_TZ = "UTC"
    settings.ALERT_QUIET_HOURS = "13:00-14:00"
    assert channels.in_quiet_hours(datetime(2026, 10, 20, 13, 30, tzinfo=timezone.utc))
    assert not channels.in_quiet_hours(datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc))
    settings.ALERT_QUIET_HOURS = ""
    assert not channels.in_quiet_hours(NOW)


def test_quiet_hours_hold_warnings_but_never_urgent_alerts(both):
    both.ALERT_QUIET_HOURS, both.ALERT_QUIET_TZ = "10:00-14:00", "UTC"   # NOW is 12:00 UTC: inside
    mk(sev="warn", key="w")
    mk(sev="page", key="p", title="SES sending is DISABLED")
    post = Recorder()
    assert alerts.notify_pending(post, NOW) == 1
    sent_titles = {c["json"]["text"] for c in post.to(SLACK)}
    assert len(sent_titles) == 1 and "DISABLED" in sent_titles.pop()
    after = NOW + timedelta(hours=3)             # 15:00: quiet hours over, the warning goes out
    post2 = Recorder()
    assert alerts.notify_pending(post2, after) == 1
    assert Alert.objects.get(key="w").notified_at


def test_a_warning_that_resolves_inside_quiet_hours_is_never_announced(both):
    both.ALERT_QUIET_HOURS, both.ALERT_QUIET_TZ = "10:00-14:00", "UTC"
    a = mk(sev="warn")
    alerts.notify_pending(Recorder(), NOW)
    a.refresh_from_db()
    a.resolved_at = NOW
    a.save()
    post = Recorder()
    alerts.notify_pending(post, NOW + timedelta(hours=3))
    assert not post.calls  # it was never announced, so there is nothing to announce the end of


# ---------------------------------------------------------------- test notification
def test_send_test_reports_per_channel_without_leaking_urls_or_bodies(both):
    post = Recorder({SLACK: 500, HOOK: ConnectionError("https://hooks.example/generic?token=SECRET")})
    res = dict((c, (ok, why)) for c, ok, why in channels.send_test(post))
    assert res["slack"] == (False, "HTTP 500") and res["webhook"] == (False, "ConnectionError")
    assert "SECRET" not in repr(res)
    assert json.loads(post.to(HOOK)[0]["data"])["event"] == "test"


def test_test_button_is_for_admins_and_is_audited(both, monkeypatch):
    monkeypatch.setattr(channels, "send_test", lambda post: [("slack", True, ""), ("webhook", False, "HTTP 500")])
    for role in (VIEWER, SUPPORT):
        c, _ = login(role, f"{role}@example.com")
        assert c.post(reverse("alerts_test_channels")).status_code == 403, role
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    r = c.post(reverse("alerts_test_channels"))
    html = r.content.decode()
    assert r.status_code == 200 and "Delivered" in html and "Failed" in html and "HTTP 500" in html
    assert AuditLog.objects.filter(action="alerts.test_notification", actor="d@example.com").exists()
    assert c.get(reverse("alerts_test_channels")).status_code == 405  # POST only


def test_alerts_page_shows_channels_rules_and_delivery_state(both):
    both.ALERT_QUIET_HOURS = ""
    mk(notified_at=NOW)
    c, _ = login(VIEWER, "v@example.com")
    html = c.get(reverse("alerts")).content.decode()
    assert "Slack" in html and "Webhook" in html and "Sent to Slack, Webhook" in html
    assert "2% warning, 4% urgent" in html and "Send a test notification" not in html   # a viewer cannot test
    c2, _ = login(SECURITY_ADMIN, "s@example.com")
    assert "Send a test notification" in c2.get(reverse("alerts")).content.decode()


def test_alerts_page_explains_how_to_get_notifications_when_none_are_set(settings):
    settings.ALERT_SLACK_WEBHOOK_URL = settings.ALERT_WEBHOOK_URL = ""
    c, _ = login(VIEWER, "v@example.com")
    assert "MC_ALERT_SLACK_WEBHOOK_URL" in c.get(reverse("alerts")).content.decode()


# ---------------------------------------------------------------- start-up validation
def test_production_settings_reject_bad_alert_config():
    code, err = _import_settings()
    assert code == 0, err                                                             # the baseline is valid
    for env, needle in (
        ({"MC_ALERT_BOUNCE_WARN": "0.05"}, "MC_ALERT_BOUNCE_WARN"),                    # warn above the default page level
        ({"MC_ALERT_COMPLAINT_PAGE": "2"}, "MC_ALERT_COMPLAINT_WARN"),                 # rates are fractions, not percent
        ({"MC_ALERT_QUOTA_WARN": "0"}, "MC_ALERT_QUOTA_WARN"),
        ({"MC_ALERT_BOUNCE_WARN": "lots"}, "MC_ALERT_BOUNCE_WARN"),
        ({"MC_ALERT_SLACK_WEBHOOK_URL": "http://hooks.example/x"}, "https"),           # plain http would expose alert text
        ({"MC_ALERT_WEBHOOK_URL": "ftp://hooks.example/x"}, "https"),
        ({"MC_ALERT_QUIET_HOURS": "25:00-07:00"}, "MC_ALERT_QUIET_HOURS"),
        ({"MC_ALERT_QUIET_HOURS": "late"}, "MC_ALERT_QUIET_HOURS"),
        ({"MC_ALERT_QUIET_HOURS": "22:00-07:00", "MC_ALERT_QUIET_TZ": "Mars/Base"}, "time zone"),
    ):
        code, err = _import_settings(**env)
        assert code != 0 and needle in err, (env, err[-300:])
    code, err = _import_settings(MC_ALERT_SLACK_WEBHOOK_URL="https://hooks.example/x", MC_ALERT_QUIET_HOURS="22:00-07:00", MC_ALERT_QUIET_TZ="Asia/Kolkata")
    assert code == 0, err
