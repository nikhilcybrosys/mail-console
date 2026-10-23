"""Long-running SQS consumer for DMARC reports that arrive by mail. Run as its own container next to the event worker."""
import logging
import pathlib
import time

import boto3
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.audit.service import record
from apps.inbound import dmarc_mail
from apps.inbound.dmarc_mail import OverLimit
from apps.sesdata.events import IgnoredMessage, ParseError, UnexpectedTopic

log = logging.getLogger(__name__)
PRUNE_EVERY = 3600


class Command(BaseCommand):
    help = "Consume DMARC report mail notifications from SQS and store the reports"

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Drain one batch and exit (tests/ops)")

    def handle(self, *args, once, **opts):
        if not settings.DMARC_ENABLED:
            raise CommandError("DMARC collection is off: set MC_SQS_DMARC_QUEUE_URL and the other MC_DMARC_* settings")
        url = settings.DMARC_QUEUE_URL
        region = url.split(".")[1]
        sqs, s3 = boto3.client("sqs", region_name=region), boto3.client("s3", region_name=region)
        fetch, last_prune = dmarc_mail.s3_fetcher(s3), 0.0
        while True:
            self.drain(sqs, url, fetch)
            if time.monotonic() - last_prune > PRUNE_EVERY:
                last_prune = time.monotonic()
                dmarc_mail.prune()
            if once:
                return
            time.sleep(0.2)

    def drain(self, sqs, url, fetch):
        try:  # the container health check fails if this file stops being refreshed
            pathlib.Path(settings.WORKER_HEARTBEAT_FILE).touch()
        except OSError:
            pass
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=20, VisibilityTimeout=120,
                                   AttributeNames=["ApproximateReceiveCount"])
        for m in resp.get("Messages", []):
            try:
                notice = dmarc_mail.read_notice(m["Body"], settings.DMARC_TOPIC_ARNS)
                dmarc_mail.process(notice, fetch)
            except UnexpectedTopic as exc:
                # Anomalous: leave it so it lands in the dead-letter queue and raises the alarm.
                record("dmarc.mail.rejected_topic", details={"message_id": m["MessageId"], "error": str(exc)[:200]})
                continue
            except OverLimit as exc:
                # Kept on purpose: it retries, then lands in the dead-letter queue, from where it can be recovered.
                log.warning("kept %s: %s", m["MessageId"], exc)
                continue
            except IgnoredMessage as exc:
                log.info("ignored control message %s: %s", m["MessageId"], exc)  # then deleted below
            except ParseError as exc:
                log.warning("unparseable notification %s: %s", m["MessageId"], exc)
                continue
            except Exception:  # S3 or database trouble: retry through the visibility timeout, then the dead-letter queue
                log.exception("failed to process %s", m["MessageId"])
                continue
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
