"""Long-running SQS consumer. Run as the `worker` ECS task."""
import logging
import pathlib
import time

import boto3
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.audit.service import record
from apps.sesdata.events import IgnoredMessage, ParseError, UnexpectedTopic
from apps.sesdata.ingest import process_body

log = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Consume SES events from SQS and store them"

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Drain one batch and exit (tests/ops)")
        parser.add_argument("--queue-url", default="")

    def handle(self, *args, once, queue_url, **opts):
        queue_url = queue_url or settings.SQS_EVENTS_QUEUE_URL
        if not queue_url:
            raise CommandError("MC_SQS_EVENTS_QUEUE_URL not set")
        if not settings.EXPECTED_SNS_TOPIC_ARNS:
            # Fail closed: without an allow-list every SNS envelope would be rejected anyway.
            raise CommandError("MC_EXPECTED_SNS_TOPIC_ARNS must list the SES SNS topic ARN(s)")
        sqs = boto3.client("sqs")
        while True:
            self.drain(sqs, queue_url)
            if once:
                return
            time.sleep(0.2)

    def drain(self, sqs, queue_url):
        try:  # the container health check fails if this file stops being refreshed
            pathlib.Path(settings.WORKER_HEARTBEAT_FILE).touch()
        except OSError:
            pass
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=20,
                                   VisibilityTimeout=120, AttributeNames=["ApproximateReceiveCount"])
        for m in resp.get("Messages", []):
            try:
                process_body(m["Body"], settings.EXPECTED_SNS_TOPIC_ARNS)
            except UnexpectedTopic as exc:
                # Anomalous: leave on queue so it lands in the DLQ and raises the DLQ alarm.
                record("ingest.rejected_topic", details={"message_id": m["MessageId"], "error": str(exc)[:200]})
                continue
            except IgnoredMessage as exc:
                log.info("ignored control message %s: %s", m["MessageId"], exc)  # then deleted below
            except ParseError as exc:
                log.warning("unparseable message %s: %s", m["MessageId"], exc)
                continue
            except Exception:  # transient DB error etc.: retry via visibility timeout
                log.exception("failed to process %s", m["MessageId"])
                continue
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
