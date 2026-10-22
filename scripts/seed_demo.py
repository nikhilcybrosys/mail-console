"""Seed SYNTHETIC demo data into the dev database. Never run against anything real.

    MC_DEBUG=1 MC_SECRET_KEY=dev MC_DB_PORT=54329 .venv/bin/python scripts/seed_demo.py
"""
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("MC_DEBUG", "1")
os.environ.setdefault("MC_SECRET_KEY", "dev")
import django  # noqa: E402

django.setup()
if not os.environ.get("MC_DEBUG") == "1":
    sys.exit("refusing: seed only runs with MC_DEBUG=1")

from apps.accounts.models import User  # noqa: E402
from apps.approvals import service  # noqa: E402
from apps.sesdata import sync  # noqa: E402
from apps.sesdata.ingest import process_body  # noqa: E402
from apps.sesdata.models import Alert, AwsAccount, DnsCheckResult, Message, SuppressionEntry  # noqa: E402
from apps.sesdata import sample_events as f  # noqa: E402

def seed_inbound():
    """Inbox, attachments, one DMARC report, and a bulk-removal request that another person must approve. Idempotent."""
    from datetime import datetime, timedelta, timezone as tz
    from apps.inbound.models import DmarcReport, InboundAttachment, InboundMessage
    from apps.approvals.models import ApprovalRequest
    if InboundMessage.objects.exists():
        return
    now = datetime.now(tz.utc)
    rows = [("bob@acme.io", "Re: Your payment receipt", {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}, "mail", True),
            ("maria@globex.com", "Re: Reset your password", {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}, "mail", False),
            ("mailer-daemon@googlemail.com", "Delivery Status Notification (Failure)", {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}, "bounce", False),
            ("noreply-dmarc-support@google.com", "Report domain: example.com Submitter: google.com", {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}, "dmarc_report", True),
            ("prince@scam-example.net", "URGENT invoice attached", {"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"}, "mail", True)]
    made = []
    for i, (frm, subj, v, kind, att) in enumerate(rows):
        m = InboundMessage.objects.create(aws_account_id=ACC, region=REG, archive_message_id=f"demo-in-{i}", received_at=now - timedelta(hours=3 * i + 1), from_addr=frm,
                                          to_addrs=["support@inbound.example.com"], subject=subj, verdicts=v, size=18000 + i * 4100, has_attachments=att, kind=kind, thread_key=f"<t{i}@demo>")
        made.append(m)
    InboundAttachment.objects.create(message=made[0], index=0, filename="receipt-4411.pdf", content_type="application/pdf", size=84211, s3_key="demo/a0", scan_state="clean")
    InboundAttachment.objects.create(message=made[3], index=0, filename="google.com!example.com!1761004800.xml.gz", content_type="application/gzip", size=1904, s3_key="demo/a1", scan_state="clean")
    InboundAttachment.objects.create(message=made[4], index=0, filename="invoice.exe", content_type="application/octet-stream", size=402113, s3_key="demo/a2", scan_state="infected")
    DmarcReport.objects.create(message=made[3], org_name="google.com", report_id="demo-1", domain="example.com", begin=now - timedelta(days=1), end=now, policy="none", pass_count=412, fail_count=17,
                               rows=[{"source_ip": "203.0.113.9", "count": 17, "dkim": "fail", "spf": "fail", "disposition": "none", "header_from": "example.com"}])
    dl = User.objects.get(email="deliv@demo.example.com")
    if not ApprovalRequest.objects.filter(requested_by=dl).exists():
        service.request_action(dl, "suppression.remove", {"addresses": [f"old{i}@legacy-customer.com" for i in range(60)]}, REG, "Demo: clean up addresses from a migrated customer list")
    print("seeded inbound demo data")


random.seed(7)
ACC, REG = "111122223333", "ap-south-1"
ACC, REG = "111122223333", "ap-south-1"
if Message.objects.exists():
    seed_inbound()
    sys.exit("messages already present; inbound demo data ensured")
AwsAccount.objects.get_or_create(alias="demo", defaults={"aws_account_id": ACC})
now = datetime.now(timezone.utc)
iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z")  # noqa: E731
APPS = ["webapp", "webapp", "billing", "watchdog"]
SUBJECTS = ["Welcome to Acme", "Your payment receipt", "Reset your password", "Trial ends in 3 days", "Payment Received"]
n = 0
for h in range(47, -1, -1):
    for _ in range(random.randint(3, 9)):
        t = now - timedelta(hours=h, minutes=random.randint(0, 55))
        n += 1
        mid, rcpt = f"demo{n:05d}-0000-0000", f"user{n}@{random.choice(['acme.io', 'globex.com', 'initech.co', 'gmail.com'])}"
        app, subj = random.choice(APPS), random.choice(SUBJECTS)
        kw = dict(mid=mid, ts=iso(t), dest=(rcpt,), subject=subj, tags={"mc-app": [app]})
        rest = {k: v for k, v in kw.items() if k not in ("dest", "ts")}
        for ev in (f.send(**kw),):
            process_body(f.sns(ev), [f.TOPIC])
        r = random.random()
        if r < 0.90:
            process_body(f.sns(f.delivery(ts=iso(t + timedelta(seconds=3)), rcpts=(rcpt,), **rest)), [f.TOPIC])
        elif r < 0.95:
            sub = random.choice(["General", "NoEmail", "OnAccountSuppressionList"])
            process_body(f.sns(f.bounce(ts=iso(t + timedelta(seconds=5)), sub=sub, rcpts=(rcpt,), feedback=f"fb{n}", **rest)), [f.TOPIC])
        elif r < 0.97:
            process_body(f.sns(f.delay(ts=iso(t + timedelta(minutes=1)), **rest)), [f.TOPIC])
        elif r < 0.975:
            process_body(f.sns(f.delivery(ts=iso(t + timedelta(seconds=3)), rcpts=(rcpt,), **rest)), [f.TOPIC])
            process_body(f.sns(f.complaint(ts=iso(t + timedelta(hours=1)), rcpts=(rcpt,), **rest)), [f.TOPIC])


class Demo:  # fake reader: no AWS involved
    def get_account(self):
        return {"ProductionAccessEnabled": True, "SendingEnabled": True, "EnforcementStatus": "HEALTHY", "SendQuota": {"Max24HourSend": 50000.0, "MaxSendRate": 14.0, "SentLast24Hours": 612.0}}

    def list_identities(self):
        return [{"IdentityName": "example.com", "IdentityType": "DOMAIN"}]

    def get_identity(self, name):
        return {"IdentityType": "DOMAIN", "VerifiedForSendingStatus": True, "ConfigurationSetName": "mc-default",
                "DkimAttributes": {"Status": "SUCCESS", "Tokens": ["tok1", "tok2", "tok3"], "SigningAttributesOrigin": "AWS_SES"},
                "MailFromAttributes": {"MailFromDomain": "mail.example.com", "MailFromDomainStatus": "SUCCESS"}}

    def list_config_sets(self):
        return ["mc-default", "mc-archive"]

    def get_config_set(self, n):
        return {"SendingOptions": {"SendingEnabled": True}, "TrackingOptions": {}}

    def get_event_destinations(self, n):
        return [{"Name": "sns-events", "Enabled": True}] if n == "mc-default" else []

    def iter_suppressed(self):
        for a, r in (("Bounced.User@Example.com", "BOUNCE"), ("angry@globex.com", "COMPLAINT"), ("gone@initech.co", "BOUNCE")):
            yield {"EmailAddress": a, "Reason": r, "LastUpdateTime": now - timedelta(days=3)}


d = Demo()
sync.sync_account(d, ACC, REG)
sync.sync_identities(d, ACC, REG)
sync.sync_config_sets(d, ACC, REG)
sync.sync_suppression(d, ACC, REG)
# DNS results mirroring what the plan found for example.com today (illustrative, not a live lookup)
for t in ("tok1", "tok2", "tok3"):
    DnsCheckResult.objects.create(domain="example.com", record_kind="dkim", ok=True, expected=[f"{t}.dkim.amazonses.com"], actual=[f"{t}.dkim.amazonses.com"])
DnsCheckResult.objects.create(domain="example.com", record_kind="spf", ok=False, expected=["v=spf1 ... include:amazonses.com ~all"], actual=[], detail="No SPF record. Receivers may treat mail as unauthenticated.")
DnsCheckResult.objects.create(domain="example.com", record_kind="dmarc", ok=False, expected=["p=quarantine|reject with rua"], actual=["v=DMARC1; p=none"], detail="p=none is monitoring only (no enforcement); no rua= aggregate report address")
Alert.objects.create(key="demo", severity="warn", title="DNS SPF problem for example.com", detail="No SPF record.")
for e, role in (("admin@example.com", "security_admin"), ("support@demo.example.com", "support"), ("viewer@demo.example.com", "viewer"), ("deliv@demo.example.com", "deliverability_admin")):
    User.objects.get_or_create(email=e, defaults={"role": role})
req = User.objects.get(email="admin@example.com")
service.request_action(req, "account.sending", {"enabled": False}, REG, "Demo: pause sending during an incident drill")
seed_inbound()
print("seeded", Message.objects.count(), "messages")
