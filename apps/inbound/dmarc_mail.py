"""DMARC aggregate reports that arrive by mail at the reports address.

The path is: SES receives the mail, stores the raw message in S3 and publishes a notification (SNS -> SQS). This module turns
one such notification into stored reports, and records what happened to the mail in `DmarcMail`.

Anyone on the internet can send mail to that address, so nothing here is trusted until it has been checked:

* the notification must come from an allowed topic, be for exactly our address, and carry passing virus and DMARC verdicts
  (SES's own checks of the sender) and no spam failure;
* the bucket is OUR configured bucket, never the one named in the notification, and the object key must sit under our prefix;
* size limits apply before anything is parsed (object size, number of parts, number and size of attachments);
* attachments then go through the same strict validation as a manual upload (`dmarc_upload.store_report`).

A passing DMARC check proves who SENT the mail, not that the sender is a genuine reporting provider. So the sender's domain is
stored with every report (it is part of the uniqueness key: another sender cannot take a genuine report's slot), reports from
senders on the operator's list (MC_DMARC_SENDERS: exact domains or exact addresses, never subdomains) are "inbox" (verified) and reports from any other authenticated
sender are "mail" (stored, counted, labelled unverified like uploads).

Daily allowances are kept in separate pools so strangers cannot use up the allowance of the providers you list: mail that failed
the notification checks (nothing in it is trusted, not even its From), listed senders, other authenticated senders, and each
sender on its own. An exhausted allowance raises OverLimit: the message is NOT deleted, it stays on the queue and ends in the
dead-letter queue, where it can still be recovered.

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
from django.db.models import Q
from django.utils import timezone as djtz

from apps.sesdata.events import ParseError, unwrap

from . import dmarc_upload
from .models import DmarcMail

log = logging.getLogger(__name__)
MAX_OBJECT_BYTES = 5 * 1024 * 1024   # the whole raw mail; real reports are a few KB to a few hundred KB
MAX_PARTS = 10
MAX_ATTACHMENTS = 3
KEEP_DAYS = 90
UNAUTHENTICATED_MAX_PER_DAY = 500   # log lines for mail that failed the notification checks (cheap: nothing is fetched or parsed)
_KEY_TAIL = re.compile(r"[A-Za-z0-9._-]{1,200}")
_ID = re.compile(r"[A-Za-z0-9._=+-]{1,200}")
_ADDR = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}")


class OverLimit(Exception):
    """A daily allowance is used up. Not a refusal: the message is kept (queue, then dead-letter queue), never silently deleted."""


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


def _sender(common):
    """The header From as ONE exact address, or "" if there is not exactly one plain mailbox.

    Parsed with the strict RFC parser, never searched for with a pattern: a display name such as '"ceo@good.example" <x@evil.example>'
    must yield x@evil.example, which is what SES's DMARC check was about. The envelope sender is never a fallback.
    """
    values = common.get("from") if isinstance(common, dict) else None
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str) or len(values[0]) > 998:
        return ""
    try:
        header = email.policy.default.header_factory("From", values[0])
    except Exception:  # noqa: BLE001: hostile header text can fail in odd ways
        return ""
    if header.defects or len(header.addresses) != 1 or len(header.groups) != 1 or header.groups[0].display_name is not None:
        return ""
    addr = header.addresses[0].addr_spec
    return addr.lower() if _ADDR.fullmatch(addr) else ""


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
    sender = _sender(mail.get("commonHeaders"))
    verdicts = {k: _status(receipt, f"{k}Verdict") for k in ("virus", "spam", "dmarc", "dkim", "spf")}
    return Notice(mid, _ts(mail.get("timestamp") or receipt.get("timestamp"), now), sender, recipients, verdicts,
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
    if not n.from_addr:
        raise Refused("the message has no single, plain sender address")
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


def _record(n, outcome, reason="", reports=0, sender_domain=""):
    row, _ = DmarcMail.objects.get_or_create(
        ses_message_id=n.ses_message_id,
        defaults={"received_at": n.received_at, "from_addr": n.from_addr, "outcome": outcome, "reason": reason[:300], "reports": reports,
                  "sender_domain": sender_domain})
    return row


def _domain(addr):
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def is_listed(addr, senders):
    """Is this authenticated sender on the operator's list? An entry is a domain (exactly that domain, not its subdomains) or a
    full address (exactly that address). Entries are matched whole, never as suffixes or patterns."""
    return bool(addr) and any(e in (addr, _domain(addr)) for e in senders)


def _listed_q(senders):
    q = Q(pk__in=[])
    for e in senders:
        q |= Q(from_addr=e) if "@" in e else Q(sender_domain=e)
    return q


def _rows(now):
    return DmarcMail.objects.filter(created_at__gte=now - timedelta(days=1)).exclude(ses_message_id__startswith="limit-")


def _over(now, pool, text):
    """Say once per day, in the log, that an allowance is used up (a flood cannot grow the table), then keep the message."""
    DmarcMail.objects.get_or_create(ses_message_id=f"limit-{now:%Y-%m-%d}-{pool}", defaults={"received_at": now, "outcome": "refused", "reason": text[:300]})
    raise OverLimit(text)


def process(n, fetch, *, now=None, allowed=None, address=None, bucket=None, prefix=None, senders=None):
    """Handle one notice. `fetch(bucket, key)` returns the raw mail bytes (raising ObjectTooLarge / ObjectGone, or anything
    else for a genuine fault). Returns the DmarcMail row. Safe to call again for the same message. Raises OverLimit when a
    daily allowance is used up (the caller keeps the message)."""
    now = now or djtz.now()
    address = settings.DMARC_ADDRESS if address is None else address
    bucket = settings.DMARC_BUCKET if bucket is None else bucket
    prefix = settings.DMARC_KEY_PREFIX if prefix is None else prefix
    senders = settings.DMARC_SENDERS if senders is None else senders
    done = DmarcMail.objects.filter(ses_message_id=n.ses_message_id).first()
    if done:
        return done
    # 1. What the notification alone can tell us. Until SES's DMARC check has passed, the From address is unauthenticated: it
    #    could name anyone, so it is not recorded as a sender and cannot count against anyone's allowance.
    try:
        check_notice(n, address=address, bucket=bucket, prefix=prefix)
    except Refused as why:
        if _rows(now).filter(sender_domain="").count() >= UNAUTHENTICATED_MAX_PER_DAY:
            _over(now, "unauthenticated", f"{UNAUTHENTICATED_MAX_PER_DAY} mails a day that failed the checks were logged; the rest are kept on the queue")
        return _record(n, "refused", str(why))
    # 2. Authenticated sender: allowances, per pool and per sender.
    domain = _domain(n.from_addr)    # never empty here: check_notice refused a message without one plain sender address
    trusted = is_listed(n.from_addr, senders)
    pool = _rows(now).exclude(sender_domain="")
    if trusted and pool.filter(_listed_q(senders)).count() >= settings.DMARC_MAX_PER_DAY:
        _over(now, "listed", f"the daily allowance of {settings.DMARC_MAX_PER_DAY} mails from your listed providers is used up")
    if not trusted and pool.exclude(_listed_q(senders)).count() >= settings.DMARC_UNLISTED_MAX_PER_DAY:
        _over(now, "unlisted", f"the daily allowance of {settings.DMARC_UNLISTED_MAX_PER_DAY} mails from senders that are not on your list is used up")
    if pool.filter(from_addr=n.from_addr).count() >= settings.DMARC_MAX_PER_SENDER:
        _over(now, "sender-" + re.sub(r"[^a-z0-9.@_%+-]", "", n.from_addr)[:80], f"{n.from_addr} has used its daily allowance of {settings.DMARC_MAX_PER_SENDER} mails")
    # 3. The message itself.
    try:
        raw = fetch(n.bucket, n.key)
        files = attachments(raw)
    except Refused as why:
        return _record(n, "refused", str(why), sender_domain=domain)
    allowed = dmarc_upload.watched_domains() if allowed is None else allowed
    source = "inbox" if trusted else "mail"
    results = [dmarc_upload.store_report(data, name, source=source, allowed=allowed, now=now, sender=n.from_addr) for name, data in files]
    added = sum(r.status == "added" for r in results)
    if added:
        outcome, reason = "accepted", ""
    elif all(r.status == "duplicate" for r in results):
        outcome, reason = "duplicate", ""
    else:
        outcome, reason = "refused", next((r.detail for r in results if r.status == "error"), "no report could be stored")
    return _record(n, outcome, reason, added, sender_domain=domain)


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

