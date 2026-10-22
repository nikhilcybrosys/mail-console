"""Fetch raw MIME for a stored body and parse it. The only place that reads message content."""
import boto3
from django.conf import settings

from .mime import parse_mime
from .models import InboundMessage

MAX_BYTES = 40 * 1024 * 1024  # SES hard limit


def _s3_get(key):
    obj = boto3.client("s3").get_object(Bucket=settings.CONTENT_BUCKET, Key=key)
    if obj["ContentLength"] > MAX_BYTES:
        raise ValueError("object too large")
    return obj["Body"].read()


def load_message_body(body_ref, rules=()):
    """Outbound bodies archived for opted-in categories live in the content bucket as raw MIME."""
    return parse_mime(_s3_get(body_ref), rules)


def load_inbound_body(inbound_id, rules=()):
    m = InboundMessage.objects.filter(pk=inbound_id).first()
    if not m or not m.s3_ref:
        return None
    return parse_mime(_s3_get(m.s3_ref), rules)
