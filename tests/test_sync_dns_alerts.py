from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.utils import timezone

from apps.sesdata import alerts, dns, metrics, sync
from apps.sesdata.ingest import process_body
from apps.sesdata.models import Alert, DnsCheckResult, IdentitySnapshot, SuppressionChange, SuppressionEntry

from . import factories as f

pytestmark = pytest.mark.django_db
ACC, REG = "111122223333", "ap-south-1"


class FakeReader:
    def __init__(self):
        self.suppressed = {}
        # Real SES responses carry datetime objects (boto3 parses timestamps); the snapshot JSON columns must cope.
        self.account = {"ProductionAccessEnabled": True, "SendingEnabled": True, "EnforcementStatus": "HEALTHY",
                        "Details": {"CreatedTimestamp": datetime(2026, 1, 2, tzinfo=dt_timezone.utc)},
                        "SendQuota": {"Max24HourSend": 50000.0, "MaxSendRate": 14.0, "SentLast24Hours": 100.0}}

    def get_account(self):
        return self.account

    def list_identities(self):
        return [{"IdentityName": "example.com", "IdentityType": "DOMAIN"}]

    def get_identity(self, name):
        return {"IdentityType": "DOMAIN", "VerifiedForSendingStatus": True, "ConfigurationSetName": "mc-default",
                "VerificationInfo": {"LastCheckedTimestamp": datetime(2026, 10, 22, tzinfo=dt_timezone.utc)},
                "DkimAttributes": {"Status": "SUCCESS", "Tokens": ["t1", "t2", "t3"], "SigningAttributesOrigin": "AWS_SES"},
                "MailFromAttributes": {"MailFromDomain": "mail.example.com", "MailFromDomainStatus": "SUCCESS"}}

    def list_config_sets(self):
        return ["mc-default"]

    def get_config_set(self, n):
        return {"SendingOptions": {"SendingEnabled": True}, "TrackingOptions": {},
                "ReputationOptions": {"LastFreshStart": datetime(2026, 10, 1, tzinfo=dt_timezone.utc)}}

    def get_event_destinations(self, n):
        return [{"Name": "sns", "Enabled": True, "MatchingEventTypes": ["BOUNCE"]}]

    def iter_suppressed(self):
        yield from self.suppressed.values()


def test_sync_account_identities_configsets():
    r = FakeReader()
    snap = sync.sync_account(r, ACC, REG)
    assert snap.production_access and snap.enforcement_status == "HEALTHY" and snap.max_24h_send == 50000.0
    ids = sync.sync_identities(r, ACC, REG)
    assert ids[0].dkim_tokens == ["t1", "t2", "t3"] and ids[0].default_config_set == "mc-default"
    assert sync.sync_config_sets(r, ACC, REG)[0].destinations[0]["Name"] == "sns"


def test_suppression_sync_detects_adds_and_removals_and_keeps_case():
    r = FakeReader()
    r.suppressed = {"Bob@X.com": {"EmailAddress": "Bob@X.com", "Reason": "BOUNCE"}}
    assert sync.sync_suppression(r, ACC, REG) == (1, 0)
    assert SuppressionEntry.objects.get().address == "Bob@X.com"
    assert SuppressionEntry.objects.get().address_lower == "bob@x.com"
    r.suppressed = {"c@x.com": {"EmailAddress": "c@x.com", "Reason": "COMPLAINT"}}
    assert sync.sync_suppression(r, ACC, REG) == (1, 1)
    assert set(SuppressionChange.objects.values_list("change", flat=True)) == {"seen_added", "seen_removed"}


def test_mirror_removed_records_actor():
    SuppressionEntry.objects.create(aws_account_id=ACC, region=REG, address="a@x.com", address_lower="a@x.com", reason="BOUNCE")
    sync.mirror_removed(ACC, REG, ["a@x.com"], "sup@example.com")
    assert not SuppressionEntry.objects.exists()
    assert SuppressionChange.objects.get().actor == "sup@example.com"


def mkresolver(table):
    return lambda name, rtype: table.get((name, rtype), [])


GOOD = {
    ("t1._domainkey.example.com", "CNAME"): ["t1.dkim.amazonses.com"],
    ("t2._domainkey.example.com", "CNAME"): ["t2.dkim.amazonses.com"],
    ("t3._domainkey.example.com", "CNAME"): ["t3.dkim.amazonses.com"],
    ("example.com", "TXT"): ["v=spf1 include:_spf.google.com include:amazonses.com ~all"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"],
    ("mail.example.com", "MX"): ["10 feedback-smtp.ap-south-1.amazonses.com"],
    ("mail.example.com", "TXT"): ["v=spf1 include:amazonses.com ~all"],
}


def snapshot():
    sync.sync_identities(FakeReader(), ACC, REG)
    return IdentitySnapshot.objects.get()


def test_dns_all_good():
    res = dns.check_identity(snapshot(), mkresolver(GOOD))
    assert all(r.ok for r in res), [(r.record_kind, r.detail) for r in res if not r.ok]


def test_dns_reports_missing_spf_and_unenforced_dmarc():
    """A common real-world state: DKIM ok, no SPF record, DMARC p=none without rua."""
    table = {k: v for k, v in GOOD.items() if k[0] != "example.com" or k[1] != "TXT"}
    table[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=none"]
    res = {r.record_kind: r for r in dns.check_identity(snapshot(), mkresolver(table))}
    assert not res["spf"].ok and "No SPF" in res["spf"].detail
    assert not res["dmarc"].ok and "p=none" in res["dmarc"].detail and "rua" in res["dmarc"].detail
    assert res["dkim"].ok


@pytest.mark.parametrize("spf,expect", [
    (["v=spf1 +all"], "allows anyone"),
    (["v=spf1 include:a.com"], "terminator"),
    (["v=spf1 -all", "v=spf1 ~all"], "Multiple"),
])
def test_spf_problems(spf, expect):
    r = dns.check_spf("example.com", mkresolver({("example.com", "TXT"): spf}))
    assert not r.ok and expect in r.detail


def test_dkim_wrong_cname():
    r = dns.check_dkim("example.com", ["t1"], mkresolver({("t1._domainkey.example.com", "CNAME"): ["evil.example.com"]}))
    assert not r[0].ok


def seed(n_send=250, n_bounce=0, n_complaint=0, subtype="General"):
    for i in range(n_send):
        process_body(f.sns(f.send(mid=f"m{i}", dest=(f"u{i}@x.com",))), [f.TOPIC])
    for i in range(n_bounce):
        process_body(f.sns(f.bounce(mid=f"m{i}", rcpts=(f"u{i}@x.com",), sub=subtype, feedback=f"b{i}")), [f.TOPIC])
    for i in range(n_complaint):
        process_body(f.sns(f.complaint(mid=f"m{100 + i}", rcpts=(f"u{100 + i}@x.com",))), [f.TOPIC])


NOW = __import__("datetime").datetime(2026, 10, 20, 12, 0, tzinfo=__import__("datetime").timezone.utc)


def test_reputation_estimate_excludes_suppression_bounces():
    seed(250, n_bounce=10, subtype="OnAccountSuppressionList")
    assert metrics.reputation_estimate(48, NOW)["bounce_rate"] == 0.0
    Alert.objects.all().delete()


def test_reputation_estimate_counts_real_bounces():
    seed(250, n_bounce=10)
    est = metrics.reputation_estimate(48, NOW)
    assert est["bounces"] == 10 and est["bounce_rate"] == pytest.approx(0.04)


def test_funnel_counts():
    seed(10, n_bounce=2)
    fn = metrics.funnel(48, NOW)
    assert fn["sent"] == 10 and fn["bounced"] == 2 and fn["in_flight"] == 8


def test_alert_pages_on_high_bounce_rate_and_resolves(settings):
    seed(250, n_bounce=12)  # 4.8% >= 4% page threshold
    alerts.evaluate(NOW)
    a = Alert.objects.get(key="bounce_rate", resolved_at__isnull=True)
    assert a.severity == "page"
    # Healthy again once the window no longer contains the bad period
    alerts.evaluate(NOW + timedelta(days=10))
    assert not Alert.objects.filter(key="bounce_rate", resolved_at__isnull=True).exists()


def test_no_rate_alert_on_tiny_volume():
    seed(10, n_bounce=5)
    alerts.evaluate(NOW)
    assert not Alert.objects.filter(key__in=["bounce_rate", "complaint_rate"], resolved_at__isnull=True).exists()


def test_enforcement_and_disabled_sending_alerts():
    r = FakeReader()
    r.account.update(EnforcementStatus="PROBATION", SendingEnabled=False)
    sync.sync_account(r, ACC, REG)
    alerts.evaluate(NOW)
    keys = set(Alert.objects.filter(resolved_at__isnull=True).values_list("key", flat=True))
    assert {f"enforcement:{REG}", f"sending_disabled:{REG}"} <= keys


def test_dns_alert_one_key_per_domain_kind():
    for t in ("t1", "t2", "t3"):
        DnsCheckResult.objects.create(domain="example.com", record_kind="dkim", ok=False, expected=[t], actual=[], detail="missing")
    alerts.evaluate(NOW)
    assert Alert.objects.filter(key="dns:example.com:dkim", resolved_at__isnull=True).count() == 1


def test_notify_once_per_alert(settings):
    settings.ALERT_SLACK_WEBHOOK_URL = "https://hooks.example/test"
    Alert.objects.create(key="k", severity="page", title="T", detail="D")
    calls = []

    class R:
        def raise_for_status(self):
            pass
    post = lambda url, json, timeout, **kw: calls.append(json) or R()
    assert alerts.notify_pending(post) == 1 and alerts.notify_pending(post) == 0
    assert "T" in calls[0]["text"]


def test_notify_failure_keeps_alert_pending(settings):
    settings.ALERT_SLACK_WEBHOOK_URL = "https://hooks.example/test"
    Alert.objects.create(key="k", severity="warn", title="T")

    def boom(*a, **k):
        raise RuntimeError("down")
    assert alerts.notify_pending(boom) == 0
    assert Alert.objects.get().notified_at is None
