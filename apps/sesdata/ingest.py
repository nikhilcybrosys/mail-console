"""Apply normalized events to the database: idempotent, order-independent."""
import logging

from django.db import IntegrityError, transaction
from django.db.models import Max

from .events import ANNOTATIONS, RANK, NormalizedEvent, normalize, unwrap
from .models import MailCategory, Message, MessageEvent, MessageRecipient

log = logging.getLogger(__name__)


def stronger(current, new):
    """State after seeing `new` while at `current`: highest rank wins, annotations never change state."""
    if new in ANNOTATIONS:
        return current
    return new if RANK.get(new, 0) > RANK.get(current, 0) else current


def _source_app(tags):
    for key in ("mc-app", "app"):
        v = tags.get(key)
        if v:
            return v[0] if isinstance(v, list) else v
    return ""


def _category(tags, config_set):
    v = tags.get("mc-category")
    if v:
        return v[0] if isinstance(v, list) else v
    return MailCategory.objects.filter(config_set=config_set).values_list("name", flat=True).first() or config_set


def _get_message(ev: NormalizedEvent):
    defaults = dict(
        from_addr=ev.from_addr, from_domain=ev.from_domain, subject=ev.subject[:998], config_set=ev.config_set,
        tags=ev.tags, source_app=_source_app(ev.tags), mail_category=_category(ev.tags, ev.config_set),
        sent_at=ev.sent_at,
    )
    try:
        with transaction.atomic():
            msg, _ = Message.objects.get_or_create(
                aws_account_id=ev.aws_account_id, region=ev.region, ses_message_id=ev.ses_message_id, defaults=defaults)
    except IntegrityError:  # concurrent worker created it first
        msg = Message.objects.get(aws_account_id=ev.aws_account_id, region=ev.region, ses_message_id=ev.ses_message_id)
    return msg


@transaction.atomic
def apply_event(ev: NormalizedEvent):
    """Returns the number of NEW event rows written (0 means the whole event was a duplicate)."""
    msg = _get_message(ev)
    written = 0
    targets = ev.recipients or [""]
    for addr in targets:
        row = MessageEvent(
            message=msg, recipient=addr, event_type=ev.event_type, event_ts=ev.event_ts,
            payload=ev.payload, idempotency_key=ev.idempotency_key(addr),
        )
        try:
            with transaction.atomic():
                row.save(force_insert=True)
            written += 1
        except IntegrityError:
            continue  # duplicate delivery from SNS/SQS (at-least-once)
        if addr:
            rcpt, _ = MessageRecipient.objects.select_for_update().get_or_create(
                message=msg, address_lower=addr.lower(), defaults={"address": addr})
            new_state = stronger(rcpt.state, ev.event_type)
            if new_state != rcpt.state or (rcpt.last_event_at is None or ev.event_ts > rcpt.last_event_at):
                rcpt.state = new_state
                rcpt.last_event_at = max(filter(None, [rcpt.last_event_at, ev.event_ts]))
                rcpt.save(update_fields=["state", "last_event_at"])
    if written:
        _refresh_final_state(msg)
    return written


def _refresh_final_state(msg):
    states = list(msg.recipients.values_list("state", flat=True)) or ["send"]
    top = max(states, key=lambda s: RANK.get(s, 0))
    last = msg.recipients.aggregate(m=Max("last_event_at"))["m"]
    if top != msg.final_state or last != msg.final_state_at:
        Message.objects.filter(pk=msg.pk).update(final_state=top, final_state_at=last)


def process_body(body, expected_topics):
    """SQS body -> DB. Raises ParseError/UnexpectedTopic for the caller to route to the DLQ."""
    return apply_event(normalize(unwrap(body, expected_topics)))
