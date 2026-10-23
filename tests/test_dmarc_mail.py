"""DMARC reports arriving by mail: the notification checks, the MIME limits, idempotency and the worker's delete/retry rules."""
import email.message
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.audit.models import AuditLog
from apps.inbound import dmarc_mail, dmarcstats
from apps.inbound.dmarc_mail import ObjectGone, ObjectTooLarge, Refused
from apps.inbound.models import DmarcMail, DmarcReport
from apps.sesdata.events import IgnoredMessage, ParseError, UnexpectedTopic

from .test_dmarc_upload import ALLOWED, NOW, gz, xml, zp

pytestmark = pytest.mark.django_db
ADDR = "dmarc@reports.example.com"
BUCKET = "mc-dmarc-test"
PREFIX = "dmarc/"
TOPIC = "arn:aws:sns:ap-south-1:111122223333:mc-dmarc"
ROOT = Path(__file__).resolve().parent.parent


def notification(mid="msg0001", recipients=(ADDR,), virus="PASS", spam="PASS", dmarc="PASS", dkim="PASS", spf="PASS", bucket=BUCKET, key=None,
                 frm="noreply-dmarc-support@google.com", kind="Received", topic=TOPIC, from_header=...):
    event = {"notificationType": kind,
             "mail": {"messageId": mid, "timestamp": "2026-10-20T11:00:00.000Z", "source": "bounce@mailer.example.net",
                      "commonHeaders": {"from": [f"Google <{frm}>"] if from_header is ... else from_header}},
             "receipt": {"timestamp": "2026-10-20T11:00:01.000Z", "recipients": list(recipients),
                         "virusVerdict": {"status": virus}, "spamVerdict": {"status": spam}, "dmarcVerdict": {"status": dmarc},
                         "dkimVerdict": {"status": dkim}, "spfVerdict": {"status": spf},
                         "action": {"type": "S3", "topicArn": topic, "bucketName": bucket, "objectKey": PREFIX + mid if key is None else key}}}
    return json.dumps({"Type": "Notification", "MessageId": "sns-1", "TopicArn": topic, "Message": json.dumps(event),
                       "Timestamp": "2026-10-20T11:00:02.000Z", "SignatureVersion": "1"})


def mail(*attachments, text="Report domain: example.com", to=ADDR):
    m = email.message.EmailMessage()
    m["From"], m["To"], m["Subject"] = "noreply-dmarc-support@google.com", to, "Report Domain: example.com"
    m.set_content(text)
    for name, data, ctype in attachments:
        main, sub = ctype.split("/")
        m.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return m.as_bytes()


def one_report(rid="r1", **kw):
    return mail(("google.com!example.com!1!2.xml.gz", gz(xml(rid=rid, **kw)), "application/gzip"))


def run(raw, body=None, senders=("google.com",), **kw):
    """Process one notification whose stored mail is `raw`. Returns (DmarcMail, how many times S3 was read)."""
    reads = []

    def fetch(bucket, key):
        reads.append((bucket, key))
        if isinstance(raw, Exception):
            raise raw
        return raw

    n = dmarc_mail.read_notice(body or notification(**kw), [TOPIC], now=NOW)
    row = dmarc_mail.process(n, fetch, now=NOW, allowed=ALLOWED, address=ADDR, bucket=BUCKET, prefix=PREFIX, senders=senders)
    return row, reads


# ---------------------------------------------------------------- the notification
def test_a_real_shaped_notification_is_read_into_a_notice():
    n = dmarc_mail.read_notice(notification(), [TOPIC], now=NOW)
    assert (n.ses_message_id, n.from_addr, n.recipients, n.bucket, n.key) == ("msg0001", "noreply-dmarc-support@google.com", [ADDR], BUCKET, "dmarc/msg0001")
    assert n.verdicts == {"virus": "PASS", "spam": "PASS", "dmarc": "PASS", "dkim": "PASS", "spf": "PASS"}
    assert n.received_at == datetime(2026, 10, 20, 11, 0, tzinfo=timezone.utc)


def test_a_topic_that_is_not_allowed_is_refused_and_an_empty_allow_list_refuses_everything():
    with pytest.raises(UnexpectedTopic):
        dmarc_mail.read_notice(notification(topic="arn:aws:sns:ap-south-1:999999999999:evil"), [TOPIC])
    with pytest.raises(UnexpectedTopic):
        dmarc_mail.read_notice(notification(), [])


@pytest.mark.parametrize("body", [
    "not json", "[]", notification(kind="Bounce"),                                    # not a received-mail notification
    json.dumps({"notificationType": "Received", "mail": {"messageId": "x"}}),         # no receipt (raw delivery shape)
    notification(mid="../etc/passwd"), notification(mid=""), notification(mid="a" * 201),
])
def test_junk_and_odd_notifications_are_parse_errors_not_crashes(body):
    with pytest.raises(ParseError):
        dmarc_mail.read_notice(body, [TOPIC])


def test_the_ses_topic_validation_notice_is_ignored_not_retried():
    body = json.dumps({"Type": "Notification", "TopicArn": TOPIC, "SignatureVersion": "1", "Message": "Successfully validated SNS topic for Amazon SES event publishing."})
    with pytest.raises(IgnoredMessage):
        dmarc_mail.read_notice(body, [TOPIC])


@pytest.mark.parametrize("kw, why", [
    ({"recipients": ("someone@reports.example.com",)}, "not addressed"), ({"recipients": ()}, "not addressed"),
    ({"virus": "FAIL"}, "virus check: FAIL"), ({"virus": "PROCESSING_FAILED"}, "virus check"), ({"virus": ""}, "virus check: no result"),
    ({"spam": "FAIL"}, "spam"),
    ({"dmarc": "FAIL"}, "could not be authenticated (DMARC FAIL)"), ({"dmarc": "GRAY"}, "DMARC GRAY"), ({"dmarc": ""}, "DMARC no result"),
    ({"bucket": "someone-elses-bucket"}, "bucket"),
    ({"key": "other/msg0001"}, "outside the expected folder"), ({"key": "dmarc/"}, "outside"), ({"key": "dmarc/../secret"}, "outside"),
    ({"key": "dmarc/a/b"}, "outside"), ({"key": "dmarc/.."}, "outside"), ({"key": ""}, "outside"),
])
def test_every_check_on_the_notification_refuses_with_a_plain_reason_and_never_reads_s3(kw, why):
    row, reads = run(one_report(), **kw)
    assert row.outcome == "refused" and why in row.reason and not reads and not DmarcReport.objects.exists()


@pytest.mark.parametrize("kw", [{"spam": "PASS"}, {"spam": "GRAY"}, {"spam": "PROCESSING_FAILED"}, {"dkim": "FAIL", "spf": "FAIL"}])
def test_a_spam_that_is_not_a_failure_and_dkim_spf_alone_do_not_block_when_dmarc_passes(kw):
    assert run(one_report(rid="ok"), **kw)[0].outcome == "accepted"


def test_the_bucket_is_the_configured_one_never_what_the_notification_says():
    row, reads = run(one_report(), bucket="attacker-bucket")
    assert row.outcome == "refused" and not reads


# ---------------------------------------------------------------- the message
def test_gzip_xml_and_zip_attachments_are_all_found():
    raw = mail(("a.xml.gz", gz(xml(rid="a")), "application/gzip"), ("b.zip", zp(("b.xml", xml(rid="b"))), "application/zip"), ("c.xml", xml(rid="c"), "text/xml"))
    names = [n for n, _ in dmarc_mail.attachments(raw)]
    assert names == ["a.xml.gz", "b.zip", "c.xml"]
    row, _ = run(raw)
    assert row.outcome == "accepted" and row.reports == 3 and DmarcReport.objects.count() == 3


def test_octet_stream_is_accepted_because_providers_send_reports_that_way():
    assert run(mail(("r.xml.gz", gz(xml(rid="o")), "application/octet-stream")))[0].outcome == "accepted"


def test_a_mail_with_no_attachment_is_refused():
    row, _ = run(mail())
    assert row.outcome == "refused" and row.reason == "no report attached"


def test_too_many_attachments_or_parts_are_refused_before_any_is_parsed(monkeypatch):
    four = mail(*[(f"{i}.xml", xml(rid=f"x{i}"), "text/xml") for i in range(4)])
    row, _ = run(four, mid="m4")
    assert row.outcome == "refused" and "attachments" in row.reason and not DmarcReport.objects.exists()
    monkeypatch.setattr(dmarc_mail, "MAX_PARTS", 2)
    row, _ = run(mail(("a.xml", xml(), "text/xml")), mid="m5")
    assert "message parts" in row.reason


def test_an_oversized_attachment_is_refused_but_a_good_one_next_to_it_is_kept():
    big = b"x" * (2 * 1024 * 1024 + 1)
    row, _ = run(mail(("big.xml", big, "text/xml"), ("ok.xml", xml(rid="fine"), "text/xml")))
    assert row.outcome == "accepted" and row.reports == 1 and DmarcReport.objects.get().report_id == "fine"


def test_garbage_attachments_and_garbage_messages_are_refused_without_exceptions():
    row, _ = run(mail(("r.xml.gz", b"\x1f\x8bnot really gzip", "application/gzip")))
    assert row.outcome == "refused" and row.reason == "the file could not be read as a DMARC report (xml, gz or zip)"
    row, _ = run(b"\x00\xff\xfe not a mime message at all", mid="m2")
    assert row.outcome == "refused"


def test_a_gzip_bomb_in_a_mail_is_refused_like_in_an_upload():
    bomb = gz(b"<feedback>" + b"a" * (11 * 1024 * 1024) + b"</feedback>")
    row, _ = run(mail(("b.xml.gz", bomb, "application/gzip")))
    assert row.outcome == "refused" and "too large" in row.reason and not DmarcReport.objects.exists()


def test_entity_expansion_in_a_mailed_report_is_refused():
    evil = xml(extra='<!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>')
    row, _ = run(mail(("e.xml", evil, "text/xml")))
    assert row.outcome == "refused" and not DmarcReport.objects.exists()


def test_the_attachment_file_name_is_never_used_as_a_path_and_is_cleaned():
    raw = mail(("../../etc/passwd\x00.xml", xml(rid="p"), "text/xml"))
    ((name, _),) = dmarc_mail.attachments(raw)
    assert "\x00" not in name
    assert run(raw)[0].outcome == "accepted"


# ---------------------------------------------------------------- what is stored
def test_an_accepted_mail_stores_the_report_as_received_by_mail_not_as_an_upload():
    row, reads = run(one_report(rid="live", rows=[("203.0.113.5", 40, "pass", "pass", "none", "example.com")]))
    assert row.outcome == "accepted" and row.reports == 1 and row.from_addr == "noreply-dmarc-support@google.com"
    assert reads == [(BUCKET, "dmarc/msg0001")]
    r = DmarcReport.objects.get()
    assert (r.source, r.sender, r.uploaded_by, r.uploaded_at, r.message, r.pass_count) == ("inbox", "noreply-dmarc-support@google.com", "", None, None, 40) and len(r.file_sha256) == 64


def test_a_report_for_a_domain_the_console_does_not_watch_is_refused_with_the_reason():
    row, _ = run(one_report(domain="elsewhere.org"))
    assert row.outcome == "refused" and "elsewhere.org is not one of the domains" in row.reason and not DmarcReport.objects.exists()


def test_the_same_report_in_a_second_mail_is_a_duplicate_not_a_second_row():
    run(one_report(rid="dup"), mid="first")
    row, _ = run(one_report(rid="dup"), mid="second")
    assert row.outcome == "duplicate" and row.reports == 0 and DmarcReport.objects.count() == 1


def test_redelivery_of_the_same_queue_message_does_nothing_and_does_not_read_s3_again():
    row1, reads1 = run(one_report(rid="once"))
    row2, reads2 = run(one_report(rid="once"))
    assert row1.pk == row2.pk and reads1 and not reads2 and DmarcMail.objects.count() == 1 and DmarcReport.objects.count() == 1


def test_a_mailed_report_replaces_the_uploaded_copy_in_the_numbers():
    from .test_dmarc_upload import live_upload
    live_upload("same", n=5)
    assert dmarcstats.overview(30)[0]["total"] == 5
    now = datetime.now(timezone.utc)
    raw = mail(("r.xml", xml(rid="same", begin=now - timedelta(days=1), end=now - timedelta(hours=1), rows=[("203.0.113.5", 50, "pass", "pass", "none", "example.com")]), "text/xml"))
    n = dmarc_mail.read_notice(notification(), [TOPIC], now=now)
    assert dmarc_mail.process(n, lambda b, k: raw, now=now, allowed=ALLOWED, address=ADDR, bucket=BUCKET, prefix=PREFIX, senders=["google.com"]).outcome == "accepted"
    (o,) = dmarcstats.overview(30)
    assert o["total"] == 50 and o["uploaded"] == 0


# ---------------------------------------------------------------- faults, limits, size
def test_a_genuine_fault_propagates_and_leaves_no_trace_so_the_message_is_retried():
    with pytest.raises(RuntimeError):
        run(RuntimeError("S3 is down"))
    assert not DmarcMail.objects.exists()
    assert run(one_report(rid="later"))[0].outcome == "accepted"      # and the retry then succeeds


@pytest.mark.parametrize("exc, why", [(ObjectTooLarge("larger than 5 MB"), "larger than 5 MB"), (ObjectGone("the stored message no longer exists"), "no longer exists")])
def test_too_large_or_missing_objects_are_recorded_as_refused(exc, why):
    row, _ = run(exc)
    assert row.outcome == "refused" and why in row.reason


def test_old_log_lines_are_pruned_after_90_days_and_recent_ones_kept():
    run(one_report(rid="old"), mid="old")
    run(one_report(rid="new"), mid="new")
    DmarcMail.objects.filter(ses_message_id="old").update(created_at=NOW - timedelta(days=91))
    assert dmarc_mail.prune(NOW) == 1 and list(DmarcMail.objects.values_list("ses_message_id", flat=True)) == ["new"]


# ---------------------------------------------------------------- reading from S3
class FakeS3:
    def __init__(self, data=b"mail", length=None, head_error=None, get_error=None):
        self.data, self.length, self.head_error, self.get_error, self.gets = data, length, head_error, get_error, 0

    def head_object(self, Bucket, Key):
        if self.head_error:
            raise self.head_error
        return {"ContentLength": len(self.data) if self.length is None else self.length}

    def get_object(self, Bucket, Key):
        self.gets += 1
        if self.get_error:
            raise self.get_error
        return {"Body": SimpleNamespace(read=lambda n: self.data[:n])}


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "HeadObject")


def test_the_object_size_is_checked_before_the_body_is_requested():
    s3 = FakeS3(length=dmarc_mail.MAX_OBJECT_BYTES + 1)
    with pytest.raises(ObjectTooLarge):
        dmarc_mail.s3_fetcher(s3)(BUCKET, "dmarc/x")
    assert s3.gets == 0


def test_a_body_larger_than_the_head_claimed_is_still_capped():
    s3 = FakeS3(data=b"x" * (dmarc_mail.MAX_OBJECT_BYTES + 10), length=10)
    with pytest.raises(ObjectTooLarge):
        dmarc_mail.s3_fetcher(s3)(BUCKET, "dmarc/x")


def test_s3_returns_the_bytes_and_distinguishes_missing_from_faults():
    assert dmarc_mail.s3_fetcher(FakeS3(b"hello"))(BUCKET, "k") == b"hello"
    for code in ("404", "NoSuchKey", "NotFound"):
        with pytest.raises(ObjectGone):
            dmarc_mail.s3_fetcher(FakeS3(head_error=client_error(code)))(BUCKET, "k")
    for code in ("AccessDenied", "InternalError", "SlowDown"):
        with pytest.raises(ClientError):
            dmarc_mail.s3_fetcher(FakeS3(head_error=client_error(code)))(BUCKET, "k")


# ---------------------------------------------------------------- the worker
class FakeSQS:
    def __init__(self, bodies):
        self.messages = [{"MessageId": f"q{i}", "ReceiptHandle": f"h{i}", "Body": b} for i, b in enumerate(bodies)]
        self.deleted = []

    def receive_message(self, **kw):
        assert kw["VisibilityTimeout"] >= 60
        return {"Messages": self.messages}

    def delete_message(self, QueueUrl, ReceiptHandle):
        self.deleted.append(ReceiptHandle)


@pytest.fixture
def dmarc_on(settings, tmp_path):
    settings.DMARC_ENABLED, settings.DMARC_ADDRESS, settings.DMARC_BUCKET, settings.DMARC_KEY_PREFIX = True, ADDR, BUCKET, PREFIX
    settings.DMARC_TOPIC_ARNS, settings.WORKER_HEARTBEAT_FILE = [TOPIC], str(tmp_path / "hb")
    settings.DMARC_QUEUE_URL = "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-dmarc"
    return settings


def drain(bodies, raw=None, monkeypatch=None):
    from apps.inbound.management.commands.ingest_dmarc_mail import Command
    sqs = FakeSQS(bodies)
    monkeypatch.setattr("apps.inbound.dmarc_upload.watched_domains", lambda: ALLOWED)
    Command().drain(sqs, "url", lambda b, k: raw if not isinstance(raw, Exception) else (_ for _ in ()).throw(raw))
    return sqs.deleted


def test_the_worker_deletes_what_is_finished_and_keeps_what_needs_a_retry_or_attention(dmarc_on, monkeypatch):
    good = notification(mid="g1")
    refused = notification(mid="r1", virus="FAIL")                       # refused is a finished outcome: recorded and deleted
    wrong_topic = notification(mid="t1", topic="arn:aws:sns:ap-south-1:999999999999:evil")
    junk = "not json at all"
    assert drain([good, refused, wrong_topic, junk], raw=one_report(rid="w"), monkeypatch=monkeypatch) == ["h0", "h1"]
    assert AuditLog.objects.filter(action="dmarc.mail.rejected_topic").exists()
    assert set(DmarcMail.objects.values_list("ses_message_id", flat=True)) == {"g1", "r1"}


def test_the_worker_keeps_the_message_when_s3_or_the_database_fails(dmarc_on, monkeypatch):
    assert drain([notification(mid="f1")], raw=RuntimeError("S3 down"), monkeypatch=monkeypatch) == []
    assert not DmarcMail.objects.exists()


def test_the_worker_deletes_the_topic_validation_notice(dmarc_on, monkeypatch):
    body = json.dumps({"Type": "Notification", "TopicArn": TOPIC, "SignatureVersion": "1", "Message": "Successfully validated SNS topic for Amazon SES event publishing."})
    assert drain([body], raw=b"", monkeypatch=monkeypatch) == ["h0"]


def test_the_worker_refuses_to_start_when_collection_is_off(settings):
    settings.DMARC_ENABLED = False
    with pytest.raises(CommandError, match="DMARC collection is off"):
        call_command("ingest_dmarc_mail", "--once")


def test_the_worker_touches_its_heartbeat_file(dmarc_on, monkeypatch):
    drain([], raw=b"", monkeypatch=monkeypatch)
    assert Path(dmarc_on.WORKER_HEARTBEAT_FILE).exists()


# ---------------------------------------------------------------- configuration is validated at start-up
def _settings(**env):
    base = {"MC_SECRET_KEY": "x" * 60, "MC_DEBUG": "0", "MC_CONSOLE_HOST": "console.test", "MC_MAILVIEW_HOST": "mailview.test", "MC_DB_PORT": "54329",
            "MC_WEBAUTHN_ORIGIN": "https://console.test"}
    code = "import django.conf, os; os.environ['DJANGO_SETTINGS_MODULE']='config.settings'; from config import settings; print(settings.DMARC_ENABLED)"
    import os
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env={**os.environ, **base, **env}, capture_output=True, text=True)
    return proc


GOOD = {"MC_SQS_DMARC_QUEUE_URL": "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-dmarc", "MC_DMARC_TOPIC_ARNS": TOPIC, "MC_DMARC_ADDRESS": ADDR, "MC_DMARC_BUCKET": BUCKET}


def test_collection_is_off_by_default_and_a_good_configuration_turns_it_on():
    assert _settings().stdout.strip() == "False"
    assert _settings(**GOOD).stdout.strip() == "True"


@pytest.mark.parametrize("bad", [
    {"MC_DMARC_TOPIC_ARNS": ""}, {"MC_DMARC_TOPIC_ARNS": "not-an-arn"}, {"MC_DMARC_ADDRESS": "*@reports.example.com"}, {"MC_DMARC_ADDRESS": ""},
    {"MC_DMARC_BUCKET": "Bad Bucket"}, {"MC_DMARC_BUCKET": ""}, {"MC_DMARC_KEY_PREFIX": "dmarc"}, {"MC_DMARC_KEY_PREFIX": "../x/"}, {"MC_DMARC_KEY_PREFIX": "a//b/"},
    {"MC_DMARC_MAX_PER_DAY": "0"}, {"MC_SQS_DMARC_QUEUE_URL": "http://localhost:4566/queue"},
])
def test_a_bad_configuration_stops_the_app_from_starting(bad):
    proc = _settings(**{**GOOD, **bad})
    assert proc.returncode != 0 and "DMARC collection is enabled but not configured correctly" in proc.stderr


# ---------------------------------------------------------------- the DMARC page, the setup check and the alert
def add_mail(mid, outcome="accepted", reason="", ago=timedelta(hours=1), frm="noreply@google.com"):
    now = datetime.now(timezone.utc)
    m = DmarcMail.objects.create(ses_message_id=mid, received_at=now - ago, from_addr=frm, outcome=outcome, reason=reason, reports=1 if outcome == "accepted" else 0)
    return m


def test_the_card_is_hidden_when_collection_is_off_and_nothing_ever_arrived():
    assert dmarcstats.collection(False) is None


def test_the_card_counts_the_last_7_days_and_lists_each_refusal_with_its_reason():
    add_mail("a"), add_mail("b", "duplicate"), add_mail("c", "refused", "flagged as spam"), add_mail("old", "refused", "x", ago=timedelta(days=9))
    DmarcMail.objects.filter(ses_message_id="old").update(created_at=datetime.now(timezone.utc) - timedelta(days=9))
    c = dmarcstats.collection(True)
    assert (c["accepted"], c["duplicate"], c["refused"], c["silent"]) == (1, 1, 1, False)
    assert [m.reason for m in c["refusals"]] == ["flagged as spam"]


def test_quiet_for_three_days_is_flagged_only_once_reports_have_arrived_before():
    assert dmarcstats.collection(True)["silent"] is False                         # nothing yet: waiting, not silent
    add_mail("old", ago=timedelta(hours=80))
    assert dmarcstats.collection(True)["silent"] is True
    add_mail("fresh", ago=timedelta(hours=2))
    assert dmarcstats.collection(True)["silent"] is False
    DmarcMail.objects.all().delete()
    add_mail("only-refused", "refused", "spam", ago=timedelta(hours=100))
    assert dmarcstats.collection(True)["silent"] is False                         # refusals do not count as reports arriving


def test_the_dmarc_page_shows_the_card_with_escaped_reasons_and_no_card_when_off(settings):
    from django.urls import reverse
    from apps.core.rbac import DELIVERABILITY_ADMIN
    from .test_views import login
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    settings.DMARC_ENABLED = False
    assert "Collection by mail" not in c.get(reverse("dmarc")).content.decode()
    settings.DMARC_ENABLED = True
    add_mail("r1", "refused", "<script>alert(1)</script>")
    html = c.get(reverse("dmarc")).content.decode()
    assert "Collection by mail" in html and "turned away" in html and "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


class FakeSqs:
    def __init__(self, **attrs):
        self.attrs = {"ApproximateNumberOfMessages": "0", "ApproximateNumberOfMessagesNotVisible": "0", "RedrivePolicy": "{}", "SqsManagedSseEnabled": "true", **attrs}
        self.asked = []

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        self.asked.append(QueueUrl)
        return {"Attributes": self.attrs}


def checks(settings, sqs=None):
    from apps.sesdata import setupcheck
    settings.DMARC_QUEUE_URL = "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-dmarc"
    settings.DMARC_ENABLED = True
    sqs = sqs or FakeSqs()
    return {c.key: c for c in setupcheck._dmarc_checks(datetime.now(timezone.utc), sqs)}, sqs


def test_setup_check_reads_the_dmarc_queue_and_waits_for_the_first_report_with_a_warning(settings):
    c, sqs = checks(settings)
    assert sqs.asked == [settings.DMARC_QUEUE_URL] and c["dqueue"].status == "ok" and c["darrived"].status == "warn" and "ddlq" not in c


def test_setup_check_flags_a_missing_dead_letter_queue_encryption_and_a_backlog(settings):
    c2, _ = checks(settings, FakeSqs(ApproximateNumberOfMessages="500"))
    assert c2["dqueue"].status == "warn" and "worker" in c2["dqueue"].fix
    attrs = {"ApproximateNumberOfMessages": "0"}

    class Bare(FakeSqs):
        def get_queue_attributes(self, QueueUrl, AttributeNames):
            return {"Attributes": attrs}
    c3, _ = checks(settings, Bare())
    assert c3["ddlq"].status == "warn" and c3["dsse"].status == "warn"


def test_setup_check_reports_an_unreadable_queue_without_leaking_the_error(settings):
    class Broken:
        def get_queue_attributes(self, **kw):
            err = Exception("secret detail")
            err.response = {"Error": {"Code": "AccessDenied"}}
            raise err
    c, _ = checks(settings, Broken())
    assert c["dqueue"].status == "fail" and "AccessDenied" in c["dqueue"].detail and "secret detail" not in c["dqueue"].detail


def test_setup_check_shows_arrival_age_and_refusals(settings):
    add_mail("fresh", ago=timedelta(hours=3)), add_mail("bad", "refused", "spam")
    c, _ = checks(settings)
    assert c["darrived"].status == "ok" and c["drefused"].status == "info"
    DmarcMail.objects.filter(ses_message_id="fresh").update(received_at=datetime.now(timezone.utc) - timedelta(hours=100))
    c, _ = checks(settings)
    assert c["darrived"].status == "warn"


def test_the_dmarc_group_is_only_in_run_checks_when_collection_is_on(settings):
    from apps.sesdata import setupcheck
    settings.SQS_EVENTS_QUEUE_URL = "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-events"
    settings.DMARC_ENABLED = False
    assert not [c for c in setupcheck.run_checks("ap-south-1", sqs_client=FakeSqs()) if c.group == "DMARC collection"]
    settings.DMARC_ENABLED, settings.DMARC_QUEUE_URL = True, "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-dmarc"
    assert [c for c in setupcheck.run_checks("ap-south-1", sqs_client=FakeSqs()) if c.group == "DMARC collection"]


def test_a_silent_collection_opens_one_warning_and_resolves_when_a_report_arrives(settings):
    from apps.sesdata import alerts
    from apps.sesdata.models import Alert
    settings.DMARC_ENABLED = True
    add_mail("old", ago=timedelta(hours=80))
    alerts.evaluate(), alerts.evaluate()
    (a,) = Alert.objects.filter(key="dmarc_silent", resolved_at__isnull=True)
    assert a.severity == "warn" and "DMARC" in a.title
    add_mail("new", ago=timedelta(minutes=5))
    alerts.evaluate()
    assert not Alert.objects.filter(key="dmarc_silent", resolved_at__isnull=True).exists()


def test_no_alert_when_collection_is_off(settings):
    from apps.sesdata import alerts
    from apps.sesdata.models import Alert
    settings.DMARC_ENABLED = False
    add_mail("old", ago=timedelta(hours=80))
    alerts.evaluate()
    assert not Alert.objects.filter(key="dmarc_silent").exists()


# ---------------------------------------------------------------- who SENT it: listed providers, unlisted senders, forged slots
def test_listing_a_domain_trusts_exactly_that_domain_and_listing_an_address_exactly_that_address():
    assert dmarc_mail.is_listed("noreply@google.com", ["google.com"])
    for addr in ("noreply@mail.google.com", "x@evilgoogle.com", "x@google.com.evil.org", "x@oogle.com", "", "x@com"):   # no subdomains, no suffixes
        assert not dmarc_mail.is_listed(addr, ["google.com"]), addr
    assert not dmarc_mail.is_listed("noreply@google.com", [])
    assert dmarc_mail.is_listed("dmarchelp@shared.example", ["dmarchelp@shared.example"])
    assert not dmarc_mail.is_listed("anyone@shared.example", ["dmarchelp@shared.example"])      # an address entry never trusts the whole domain
    assert not dmarc_mail.is_listed("dmarchelp@shared.example", ["elp@shared.example"])         # and is not a suffix match either
    assert not dmarc_mail.is_listed("dmarchelp@mail.shared.example", ["shared.example"])


def test_a_subdomain_of_a_listed_domain_is_not_verified_unless_listed_itself():
    row, _ = run(one_report(rid="sub"), frm="reports@mail.google.com")
    assert row.outcome == "accepted" and DmarcReport.objects.get().source == "mail"
    row, _ = run(one_report(rid="sub2"), mid="m2", frm="reports@mail.google.com", senders=["mail.google.com"])
    assert DmarcReport.objects.get(report_id="sub2").source == "inbox"


def test_a_shared_domain_can_be_trusted_by_address_without_trusting_everyone_on_it():
    senders = ["dmarchelp@shared.example"]
    assert run(one_report(rid="g"), mid="g", frm="dmarchelp@shared.example", senders=senders)[0].outcome == "accepted"
    assert run(one_report(rid="u"), mid="u", frm="some-user@shared.example", senders=senders)[0].outcome == "accepted"
    assert dict(DmarcReport.objects.values_list("report_id", "source")) == {"g": "inbox", "u": "mail"}


def test_another_user_of_a_shared_domain_cannot_take_the_slot_of_the_trusted_address():
    senders = ["dmarchelp@shared.example"]
    run(one_report(rid="same"), mid="squat", frm="some-user@shared.example", senders=senders)
    assert run(one_report(rid="same"), mid="real", frm="dmarchelp@shared.example", senders=senders)[0].outcome == "accepted"
    assert sorted(DmarcReport.objects.values_list("source", "sender")) == [("inbox", "dmarchelp@shared.example"), ("mail", "some-user@shared.example")]


# ---------------------------------------------------------------- the sender is parsed strictly, from the header From only
@pytest.mark.parametrize("header, expected", [
    (['"noreply-dmarc-support@google.com" <x@evil.example>'], "x@evil.example"),        # an address inside the display name is not the sender
    (['Google <noreply-dmarc-support@google.com> (x@evil.example)'], "noreply-dmarc-support@google.com"),
    (['X@Evil.Example'], "x@evil.example"),
    (['"a@good.example, b@good.example" <x@evil.example>'], "x@evil.example"),
    (["a@x.example, b@y.example"], ""), (["a@x.example", "b@y.example"], ""),           # more than one mailbox
    (["Group: a@x.example;"], ""), (["not an address"], ""), (['"a@good.example"'], ""), ([""], ""), ([], ""), (None, ""), ([5], ""),
    (["x" * 1000 + "@evil.example"], ""),
    (['"a b"@x.example'], ""), (["x@localhost"], ""), (["é@x.example"], ""), (["x@y_z.example"], ""),   # parse as a mailbox, but not a plain address
])
def test_the_sender_is_the_one_plain_mailbox_in_the_header_from_never_an_address_hidden_in_a_display_name(header, expected):
    n = dmarc_mail.read_notice(notification(from_header=header), [TOPIC], now=NOW)
    assert n.from_addr == expected


def test_a_display_name_naming_a_listed_provider_does_not_make_the_sender_verified():
    """The review finding: a regex search over the header picked the first address-looking text, so an attacker with a
    DMARC-aligned domain of their own could dress up as the listed provider."""
    row, _ = run(one_report(rid="dress"), from_header=['"noreply-dmarc-support@google.com" <x@evil.example>'])
    assert row.outcome == "accepted" and row.from_addr == "x@evil.example" and row.sender_domain == "evil.example"
    assert DmarcReport.objects.get().source == "mail"


def test_the_envelope_sender_is_never_a_fallback_for_who_sent_it():
    row, reads = run(one_report(), from_header=None)          # no header From in the notification, but an envelope source is present
    assert row.outcome == "refused" and "no single, plain sender address" in row.reason and not reads and row.sender_domain == ""


def test_more_than_one_mailbox_in_the_from_header_is_refused_without_reading_s3():
    row, reads = run(one_report(), from_header=["a@good.example, x@evil.example"])
    assert row.outcome == "refused" and not reads


def test_an_authenticated_sender_that_is_not_listed_is_stored_but_labelled_unverified():
    row, _ = run(one_report(rid="u1"), senders=[], frm="reports@new-provider.example")
    assert row.outcome == "accepted" and row.sender_domain == "new-provider.example"
    r = DmarcReport.objects.get()
    assert (r.source, r.sender) == ("mail", "reports@new-provider.example")


def test_a_forged_report_cannot_take_the_slot_of_the_genuine_one_and_the_genuine_one_replaces_it():
    """The review finding: with no sender in the key, whoever mailed 'google.com / r1' first made the real report a 'duplicate'."""
    kw = dict(rid="same")
    forged, _ = run(mail(("r.xml", xml(**kw, rows=[("203.0.113.9", 400, "fail", "fail", "none", "example.com")]), "text/xml")), mid="forged", frm="x@attacker.example")
    genuine, _ = run(mail(("r.xml", xml(**kw, rows=[("203.0.113.5", 50, "pass", "pass", "none", "example.com")]), "text/xml")), mid="real")
    assert (forged.outcome, genuine.outcome) == ("accepted", "accepted")                       # not "duplicate"
    assert sorted(DmarcReport.objects.values_list("source", "sender")) == [("inbox", "noreply-dmarc-support@google.com"), ("mail", "x@attacker.example")]
    (o,) = dmarcstats.overview(30)
    assert o["total"] == 50 and o["unlisted"] == 0 and o["failed"] == 0                         # only the verified copy counts


def test_unlisted_mail_is_counted_with_a_caveat_until_the_provider_is_listed():
    for i in range(10):
        r = run(mail(("r.xml", xml(rid=f"p{i}", begin=NOW - timedelta(days=i + 1), end=NOW - timedelta(days=i + 1) + timedelta(hours=23),
                                   rows=[("203.0.113.5", 30, "pass", "pass", "none", "example.com")]), "text/xml")), mid=f"m{i}", senders=[], frm="r@newco.example")[0]
        assert r.outcome == "accepted"
    (o,) = dmarcstats.overview(30)
    assert o["unlisted"] == 10 and o["state"] == "ready" and "senders you have not listed" in o["advice"] and "uploaded by hand" not in o["advice"]
    assert dmarcstats.collection(True)["unlisted_senders"] == ["r@newco.example"]


def test_the_page_labels_unlisted_senders_and_names_the_sender_of_verified_reports(settings):
    from django.urls import reverse
    from apps.core.rbac import DELIVERABILITY_ADMIN
    from .test_views import login
    settings.DMARC_ENABLED = True
    for mid, frm, senders in (("a", "n@google.com", ["google.com"]), ("b", "r@newco.example", [])):
        run(mail(("r.xml", xml(rid=mid, org=mid), "text/xml")), mid=mid, frm=frm, senders=senders)
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    html = c.get(reverse("dmarc")).content.decode()
    assert "sender not on your list" in html and "r@newco.example" in html and "received by mail from n@google.com" in html and "MC_DMARC_SENDERS" in html


def test_the_setup_check_warns_until_providers_are_listed(settings):
    settings.DMARC_SENDERS = []
    c, _ = checks(settings)
    assert c["dsenders"].status == "warn" and "MC_DMARC_SENDERS" in c["dsenders"].fix
    settings.DMARC_SENDERS = ["google.com", "yahoo.com"]
    c, _ = checks(settings)
    assert c["dsenders"].status == "ok" and "google.com, yahoo.com" in c["dsenders"].detail


# ---------------------------------------------------------------- allowances: separate pools, nothing silently deleted
def test_mail_that_failed_the_checks_cannot_use_up_a_listed_providers_allowance(settings):
    settings.DMARC_MAX_PER_DAY = 2
    for i in range(10):                                                   # unauthenticated mail CLAIMING to be from google.com
        assert run(one_report(), mid=f"spoof{i}", dmarc="FAIL")[0].sender_domain == ""
    for i in range(2):
        assert run(one_report(rid=f"g{i}"), mid=f"g{i}")[0].outcome == "accepted"      # the real sender is unaffected
    with pytest.raises(dmarc_mail.OverLimit):
        run(one_report(rid="g9"), mid="g9")                                            # and its own allowance still holds


def test_unlisted_senders_have_their_own_pool_and_cannot_starve_the_listed(settings):
    settings.DMARC_UNLISTED_MAX_PER_DAY, settings.DMARC_MAX_PER_SENDER = 2, 100
    for i in range(2):
        assert run(one_report(rid=f"s{i}"), mid=f"s{i}", frm=f"r@d{i}.example")[0].outcome == "accepted"
    with pytest.raises(dmarc_mail.OverLimit):
        run(one_report(rid="s9"), mid="s9", frm="r@d9.example")
    assert run(one_report(rid="listed"), mid="listed")[0].outcome == "accepted"        # a listed provider still gets through


def test_one_sender_cannot_use_more_than_its_own_allowance(settings):
    settings.DMARC_MAX_PER_SENDER = 2
    for i in range(2):
        run(one_report(rid=f"a{i}"), mid=f"a{i}")
    with pytest.raises(dmarc_mail.OverLimit):
        run(one_report(rid="a9"), mid="a9")
    assert run(one_report(rid="b0"), mid="b0", frm="x@yahoo.com", senders=["google.com", "yahoo.com"])[0].outcome == "accepted"


def test_an_exhausted_allowance_keeps_the_message_and_logs_one_line_a_day_not_one_per_mail(settings):
    settings.DMARC_MAX_PER_SENDER = 1
    run(one_report(rid="first"), mid="first")
    for i in range(20):
        with pytest.raises(dmarc_mail.OverLimit):
            run(one_report(rid=f"x{i}"), mid=f"x{i}")
    assert not DmarcMail.objects.filter(ses_message_id__startswith="x").exists()                    # never marked done, so it is retried
    assert DmarcMail.objects.filter(ses_message_id__startswith="limit-").count() == 1 and DmarcReport.objects.count() == 1


def test_the_unauthenticated_log_is_capped_and_the_rest_is_kept_not_deleted(monkeypatch):
    monkeypatch.setattr(dmarc_mail, "UNAUTHENTICATED_MAX_PER_DAY", 3)
    for i in range(3):
        assert run(one_report(), mid=f"j{i}", virus="FAIL")[0].outcome == "refused"
    with pytest.raises(dmarc_mail.OverLimit):
        run(one_report(), mid="j9", virus="FAIL")
    assert DmarcMail.objects.filter(ses_message_id__startswith="limit-").count() == 1


def test_the_allowances_are_a_rolling_day_so_they_free_up(settings):
    settings.DMARC_MAX_PER_SENDER = 1
    run(one_report(rid="a"), mid="a")
    with pytest.raises(dmarc_mail.OverLimit):
        run(one_report(rid="b"), mid="b")
    DmarcMail.objects.update(created_at=NOW - timedelta(days=2))
    assert run(one_report(rid="b"), mid="b")[0].outcome == "accepted"


def test_the_worker_keeps_a_message_when_an_allowance_is_used_up(dmarc_on, monkeypatch, settings):
    settings.DMARC_MAX_PER_SENDER, settings.DMARC_SENDERS = 1, ["google.com"]
    assert drain([notification(mid="w1"), notification(mid="w2")], raw=one_report(rid="w"), monkeypatch=monkeypatch) == ["h0"]


def test_sender_domains_are_validated_at_start_up():
    ok = _settings(**GOOD, MC_DMARC_SENDERS="google.com, dmarchelp@shared.example")
    assert ok.stdout.strip() == "True"
    for bad in ("*.google.com", "not a domain", "google", "https://google.com", "*@google.com", "a@b@google.com"):
        proc = _settings(**GOOD, MC_DMARC_SENDERS=bad)
        assert proc.returncode != 0 and "MC_DMARC_SENDERS" in proc.stderr


def test_the_migrations_match_the_models_so_the_database_has_the_constraints_the_code_assumes():
    from io import StringIO
    out = StringIO()
    try:
        call_command("makemigrations", "--check", "--dry-run", stdout=out, stderr=out)
    except SystemExit:
        pytest.fail("models and migrations differ: " + out.getvalue())


def test_an_unlisted_user_on_a_shared_domain_does_not_use_up_the_listed_addresss_allowance(settings):
    settings.DMARC_MAX_PER_DAY, settings.DMARC_MAX_PER_SENDER = 1, 100
    senders = ["dmarchelp@shared.example"]
    run(one_report(rid="u"), mid="u", frm="some-user@shared.example", senders=senders)        # an unlisted address, same domain
    assert run(one_report(rid="g"), mid="g", frm="dmarchelp@shared.example", senders=senders)[0].outcome == "accepted"
    with pytest.raises(dmarc_mail.OverLimit):                                                  # the listed address's own pool still holds
        run(one_report(rid="g2"), mid="g2", frm="dmarchelp@shared.example", senders=senders)


def test_each_sender_address_has_its_own_allowance_even_on_a_shared_domain(settings):
    settings.DMARC_MAX_PER_SENDER = 1
    senders = ["dmarchelp@shared.example"]
    run(one_report(rid="u"), mid="u", frm="some-user@shared.example", senders=senders)
    with pytest.raises(dmarc_mail.OverLimit):
        run(one_report(rid="u2"), mid="u2", frm="some-user@shared.example", senders=senders)
    assert run(one_report(rid="g"), mid="g", frm="dmarchelp@shared.example", senders=senders)[0].outcome == "accepted"
