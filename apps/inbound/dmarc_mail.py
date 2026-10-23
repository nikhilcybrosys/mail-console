"""DMARC aggregate reports that arrive by mail at the reports address.

The path is: SES receives the mail, stores the raw message in S3 and publishes a notification (SNS -> SQS). This module turns
one such notification into stored reports, and records what happened to the mail in `DmarcMail`.

Anyone on the internet can send mail to that address, so nothing here is trusted until it has been checked:

* the notification must come from an allowed topic, be for exactly our address, and carry passing virus and DMARC verdicts
  (SES's own checks of the sender) and no spam failure;
* the bucket is OUR configured bucket, never the one named in the notification, and the object key must sit under our prefix;
* size limits apply before anything is parsed (object size, number of parts, number and size of attachments);
* attachments then go through the same strict validation as a manual upload (`dmarc_upload.store_report`).

Mail that fails a check is not an error: it is recorded with a plain reason and dropped. A genuine fault (S3 or the database
unavailable) raises, so the message stays on the queue and is retried, then lands in the dead-letter queue.
"""
import email
import email.policy
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.utils import timezone as djtz

from apps.sesdata.events import ParseError, unwrap

from . import dmarc_upload
from .models import DmarcMail

log = logging.getLogger(__name__)
MAX_OBJECT_BYTES = 5 * 1024 * 1024   # the whole raw mail; real reports are a few KB to a few hundred KB
MAX_PARTS = 10
MAX_ATTACHMENTS = 3
KEEP_DAYS = 90
_KEY_TAIL = re.compile(r"[A-Za-z0-9._-]{1,200}")
_ID = re.compile(r"[A-Za-z0-9._=+-]{1,200}")
_ADDR = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}")


class Refused(Exception):
    """The mail is not acceptable. The message is the plain reason shown on the DMARC page."""


class ObjectTooLarge(Refused):
    pass


class ObjectGone(Refused):
    pass


@dataclass
class Notice:
    ses_message_id: str
    received_at: datetime
    from_addr: str
    recipients: list
    verdicts: dict
    bucket: str
    key: str
    problems: list = field(default_factory=list)


def _status(receipt, name):
    v = receipt.get(name)
    return str(v.get("status", "")).upper() if isinstance(v, dict) else ""


def _ts(value, fallback):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return fallback
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def read_notice(body, topics, now=None):
    """SQS body -> Notice. Raises UnexpectedTopic / IgnoredMessage / ParseError (the worker's usual three outcomes)."""
    now = now or djtz.now()
    event = unwrap(body, topics)
    if not isinstance(event, dict) or event.get("notificationType") != "Received":
        raise ParseError("not a received-mail notification")
    mail, receipt = event.get("mail"), event.get("receipt")
    if not isinstance(mail, dict) or not isinstance(receipt, dict):
        raise ParseError("notification has no mail or receipt")
    mid = mail.get("messageId")
    if not isinstance(mid, str) or not _ID.fullmatch(mid):
        raise ParseError("notification has no usable message id")
    action = receipt.get("action") if isinstance(receipt.get("action"), dict) else {}
    recipients = [str(r).strip().lower() for r in receipt.get("recipients") or [] if isinstance(r, str)][:50]
    source = mail.get("source") if isinstance(mail.get("source"), str) else ""
    common_from = (mail.get("commonHeaders") or {}).get("from") if isinstance(mail.get("commonHeaders"), dict) else None
    # The header From is what the DMARC verdict is about; the envelope sender is only the fallback.
    from_text = (common_from[0] if isinstance(common_from, list) and common_from and isinstance(common_from[0], str) else "") or source
    m = _ADDR.search(from_text)
    verdicts = {k: _status(receipt, f"{k}Verdict") for k in ("virus", "spam", "dmarc", "dkim", "spf")}
    return Notice(mid, _ts(mail.get("timestamp") or receipt.get("timestamp"), now), (m.group(0).lower() if m else "")[:320], recipients, verdicts,
                  str(action.get("bucketName") or ""), str(action.get("objectKey") or ""))


def check_notice(n, *, address, bucket, prefix):
    """Everything that can be decided from the notification alone. Raises Refused with the reason."""
    if address not in n.recipients:
        raise Refused("not addressed to the reports address")
    if n.verdicts["virus"] != "PASS":
        raise Refused(f"virus check: {n.verdicts['virus'] or 'no result'}")
    if n.verdicts["spam"] == "FAIL":
        raise Refused("flagged as spam")
    if n.verdicts["dmarc"] != "PASS":
        # DMARC PASS means the mail genuinely came from the domain in its From header (SPF or DKIM aligned with it).
        raise Refused(f"the sender could not be authenticated (DMARC {n.verdicts['dmarc'] or 'no result'})")
    if n.bucket != bucket:
        raise Refused("stored in a bucket this console does not read")
    tail = n.key[len(prefix):] if n.key.startswith(prefix) else ""
    if not _KEY_TAIL.fullmatch(tail) or tail in (".", ".."):
        raise Refused("stored outside the expected folder")


def attachments(raw):
    """Raw message bytes -> [(display name, bytes)] of the parts that could be reports. Raises Refused."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        parts = list(msg.walk())
    except Exception as exc:  # noqa: BLE001: hostile MIME can fail in odd ways; say so plainly, log only the kind
        log.warning("dmarc mail: unreadable message (%s)", type(exc).__name__)
        raise Refused("the message could not be read") from None
    if len(parts) > MAX_PARTS:
        raise Refused(f"more than {MAX_PARTS} message parts")
    found = []
    for part in parts:
        main = part.get_content_maintype()
        if main in ("multipart", "message") or (main == "text" and part.get_content_subtype() != "xml"):
            continue  # the readable body and containers are not reports
        found.append(part)
    if not found:
        raise Refused("no report attached")
    if len(found) > MAX_ATTACHMENTS:
        raise Refused(f"more than {MAX_ATTACHMENTS} attachments")
    out = []
    for part in found:
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            raise Refused("an attachment could not be decoded") from None
        out.append((dmarc_upload._text(part.get_filename() or "report", 120), data))
    return out


def _record(n, outcome, reason="", reports=0):
    row, _ = DmarcMail.objects.get_or_create(
        ses_message_id=n.ses_message_id,
        defaults={"received_at": n.received_at, "from_addr": n.from_addr, "outcome": outcome, "reason": reason[:300], "reports": reports})
    return row


def _over_the_limit(now):
    return DmarcMail.objects.filter(created_at__gte=now - timedelta(days=1)).count() >= settings.DMARC_MAX_PER_DAY


def process(n, fetch, *, now=None, allowed=None, address=None, bucket=None, prefix=None):
    """Handle one notice. `fetch(bucket, key)` returns the raw mail bytes (raising ObjectTooLarge / ObjectGone, or anything
    else for a genuine fault). Returns the DmarcMail row. Safe to call again for the same message."""
    now = now or djtz.now()
    address = settings.DMARC_ADDRESS if address is None else address
    bucket = settings.DMARC_BUCKET if bucket is None else bucket
    prefix = settings.DMARC_KEY_PREFIX if prefix is None else prefix
    done = DmarcMail.objects.filter(ses_message_id=n.ses_message_id).first()
    if done:
        return done
    if _over_the_limit(now):
        # One line per day says it happened; further mail that day is dropped without a row, so a flood cannot fill the table.
        return _record(Notice(f"limit-{now:%Y-%m-%d}", now, "", [], {}, "", ""), "refused",
                       f"daily limit of {settings.DMARC_MAX_PER_DAY} mails reached; mail after that point is dropped without being logged")
    try:
        check_notice(n, address=address, bucket=bucket, prefix=prefix)
        raw = fetch(n.bucket, n.key)
        files = attachments(raw)
    except Refused as why:
        return _record(n, "refused", str(why))
    allowed = dmarc_upload.watched_domains() if allowed is None else allowed
    results = [dmarc_upload.store_report(data, name, source="inbox", allowed=allowed, now=now) for name, data in files]
    added = sum(r.status == "added" for r in results)
    if added:
        outcome, reason = "accepted", ""
    elif all(r.status == "duplicate" for r in results):
        outcome, reason = "duplicate", ""
    else:
        outcome, reason = "refused", next((r.detail for r in results if r.status == "error"), "no report could be stored")
    return _record(n, outcome, reason, added)


def s3_fetcher(s3):
    """A `fetch` that reads from S3 with the size checked first. S3 errors other than 'no such object' propagate (retry)."""
    def fetch(bucket, key):
        from botocore.exceptions import ClientError
        try:
            head = s3.head_object(Bucket=bucket, Key=key)
            if head["ContentLength"] > MAX_OBJECT_BYTES:
                raise ObjectTooLarge(f"larger than {MAX_OBJECT_BYTES // 1024 // 1024} MB")
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read(MAX_OBJECT_BYTES + 1)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                raise ObjectGone("the stored message no longer exists") from None
            raise
        if len(body) > MAX_OBJECT_BYTES:
            raise ObjectTooLarge(f"larger than {MAX_OBJECT_BYTES // 1024 // 1024} MB")
        return body
    return fetch


def prune(now=None):
    now = now or djtz.now()
    return DmarcMail.objects.filter(created_at__lt=now - timedelta(days=KEEP_DAYS)).delete()[0]

