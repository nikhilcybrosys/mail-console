"""Parse SES event-publishing notifications (SNS envelope or raw) into normalized rows.

Pure functions, no DB access: easy to test with real-shaped payloads.
Handles both `eventType` (event publishing) and legacy `notificationType`.
"""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Terminal precedence: higher wins regardless of arrival order.
RANK = {
    "send": 10, "deliverydelay": 20, "delivery": 30,
    "renderingfailure": 40, "reject": 40, "bounce": 50, "complaint": 60,
}
ANNOTATIONS = {"open", "click", "subscription"}  # recorded, never change state
KNOWN = set(RANK) | ANNOTATIONS

# Bounce subtypes caused by our own/SES suppression: excluded from reputation estimates.
SUPPRESSION_SUBTYPES = {"OnAccountSuppressionList", "Suppressed", "OnTenantSuppressionList", "EmailValidationSuppressed"}


class ParseError(ValueError):
    pass


class UnexpectedTopic(ParseError):
    pass


class IgnoredMessage(Exception):
    """A known, harmless control message (not an event). The consumer deletes it instead of retrying."""


# SES publishes this plain-text notice to the topic when an event destination is created.
_SES_TOPIC_VALIDATION = "Successfully validated SNS topic for Amazon SES event publishing."


@dataclass
class NormalizedEvent:
    ses_message_id: str
    event_type: str  # lower-case slug
    event_ts: datetime
    recipients: list  # addresses this event applies to (original case)
    payload: dict  # the full event JSON as received
    aws_account_id: str = ""
    region: str = ""
    from_addr: str = ""
    from_domain: str = ""
    subject: str = ""
    config_set: str = ""
    tags: dict = field(default_factory=dict)
    sent_at: datetime = None
    detail: dict = field(default_factory=dict)  # bounce/complaint specifics for the explainer

    def idempotency_key(self, recipient=""):
        feedback = self.detail.get("feedbackId", "")
        raw = f"{self.ses_message_id}|{self.event_type}|{self.event_ts.isoformat()}|{recipient.lower()}|{feedback}"
        return hashlib.sha256(raw.encode()).hexdigest()


def _ts(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"bad timestamp {value!r}") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def unwrap(body, expected_topics):
    """Return the inner SES event dict from an SQS message body.

    - SNS envelope: require Type=Notification, enforce TopicArn allow-list (fail closed:
      an empty allow-list rejects everything). The SNS signature itself is not verified here: trust comes
      from the queue policy (only the pinned topic may send) plus the TopicArn allow-list. AWS creates
      topics with SignatureVersion 1 by default, so 1 and 2 are both accepted; anything else is refused.
    - Raw delivery: body is already the event; accepted only when raw delivery is configured
      and the queue policy already pins the topic (no TopicArn to check).
    """
    try:
        outer = json.loads(body)
    except (TypeError, ValueError) as exc:
        raise ParseError("body is not JSON") from exc
    if not isinstance(outer, dict):
        raise ParseError("body is not an object")
    if "Type" in outer and "Message" in outer:
        if outer["Type"] != "Notification":
            raise ParseError(f"unsupported SNS type {outer['Type']!r}")
        arn = outer.get("TopicArn", "")
        if not expected_topics or arn not in expected_topics:
            raise UnexpectedTopic(f"topic {arn!r} not allowed")
        if outer.get("SignatureVersion") not in (None, "1", "2"):
            raise ParseError("unsupported SNS SignatureVersion")
        try:
            return json.loads(outer["Message"])
        except (TypeError, ValueError) as exc:
            if isinstance(outer.get("Message"), str) and outer["Message"].strip() == _SES_TOPIC_VALIDATION:
                raise IgnoredMessage("SES topic validation notice") from exc
            raise ParseError("SNS Message is not JSON") from exc
    return outer


def _tag(tags, key):
    v = (tags or {}).get(key)
    return v[0] if isinstance(v, list) and v else (v if isinstance(v, str) else "")


def normalize(event):
    kind = event.get("eventType") or event.get("notificationType")
    if not kind:
        raise ParseError("no eventType")
    slug = kind.replace(" ", "").lower()
    if slug not in KNOWN:
        raise ParseError(f"unknown event type {kind!r}")
    mail = event.get("mail") or {}
    mid = mail.get("messageId")
    if not mid:
        raise ParseError("no mail.messageId")
    mail_ts = _ts(mail.get("timestamp"))
    if mail_ts is None:
        raise ParseError("no mail.timestamp")

    detail, recipients, ts = {}, [], None
    if slug == "bounce":
        b = event.get("bounce", {})
        recipients = [r["emailAddress"] for r in b.get("bouncedRecipients", [])]
        ts = _ts(b.get("timestamp"))
        detail = {
            "bounceType": b.get("bounceType"), "bounceSubType": b.get("bounceSubType"),
            "feedbackId": b.get("feedbackId"),
            "diagnostic": [r.get("diagnosticCode", "") for r in b.get("bouncedRecipients", [])],
            "status": [r.get("status", "") for r in b.get("bouncedRecipients", [])],
        }
    elif slug == "complaint":
        c = event.get("complaint", {})
        recipients = [r["emailAddress"] for r in c.get("complainedRecipients", [])]
        ts = _ts(c.get("timestamp"))
        detail = {"complaintFeedbackType": c.get("complaintFeedbackType"), "feedbackId": c.get("feedbackId")}
    elif slug == "delivery":
        d = event.get("delivery", {})
        recipients = list(d.get("recipients", []))
        ts = _ts(d.get("timestamp"))
        detail = {"smtpResponse": d.get("smtpResponse"), "remoteMtaIp": d.get("remoteMtaIp"), "processingTimeMillis": d.get("processingTimeMillis")}
    elif slug == "deliverydelay":
        d = event.get("deliveryDelay", {})
        recipients = [r["emailAddress"] for r in d.get("delayedRecipients", [])]
        ts = _ts(d.get("timestamp"))
        detail = {"delayType": d.get("delayType"), "expirationTime": d.get("expirationTime"),
                  "diagnostic": [r.get("diagnosticCode", "") for r in d.get("delayedRecipients", [])]}
    elif slug in ("open", "click"):
        o = event.get(slug, {})
        ts = _ts(o.get("timestamp"))
        detail = {k: o.get(k) for k in ("link", "linkTags", "isBotEvent") if k in o}
    elif slug == "reject":
        detail = {"reason": event.get("reject", {}).get("reason")}
    elif slug == "renderingfailure":
        detail = {"errorMessage": event.get("failure", {}).get("errorMessage"), "template": event.get("failure", {}).get("templateName")}
    if not recipients:
        recipients = list(mail.get("destination", []))
    tags = mail.get("tags") or {}
    source = mail.get("source", "")
    arn = mail.get("sourceArn", "")  # arn:aws:ses:REGION:ACCOUNT:identity/...
    parts = arn.split(":")
    region = parts[3] if len(parts) > 4 else ""
    account = mail.get("sendingAccountId") or (parts[4] if len(parts) > 4 else "")
    if "<" in source and ">" in source:
        addr = source[source.rfind("<") + 1:source.rfind(">")]
    else:
        addr = source
    return NormalizedEvent(
        ses_message_id=mid, event_type=slug, event_ts=ts or mail_ts, recipients=recipients, payload=event,
        aws_account_id=account, region=region, from_addr=addr, from_domain=addr.rsplit("@", 1)[-1].lower() if "@" in addr else "",
        subject=(mail.get("commonHeaders") or {}).get("subject", "") or "",
        config_set=_tag(tags, "ses:configuration-set"), tags=tags, sent_at=mail_ts, detail=detail,
    )
