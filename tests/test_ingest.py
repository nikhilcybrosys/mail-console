import json

import pytest

from apps.sesdata.events import ParseError, UnexpectedTopic, normalize, unwrap
from apps.sesdata.ingest import apply_event, process_body, stronger
from apps.sesdata.models import Message, MessageEvent, MessageRecipient

from . import factories as f

pytestmark = pytest.mark.django_db
TOPICS = [f.TOPIC]


def test_unwrap_requires_allowed_topic_and_fails_closed():
    body = f.sns(f.send())
    assert unwrap(body, TOPICS)["eventType"] == "Send"
    with pytest.raises(UnexpectedTopic):
        unwrap(f.sns(f.send(), topic="arn:aws:sns:ap-south-1:999999999999:evil"), TOPICS)
    with pytest.raises(UnexpectedTopic):
        unwrap(body, [])  # empty allow-list rejects everything


def test_unwrap_rejects_garbage_and_bad_signature_version():
    for bad in ("not json", "[]", json.dumps({"Type": "SubscriptionConfirmation", "Message": "{}"})):
        with pytest.raises(ParseError):
            unwrap(bad, TOPICS)
    with pytest.raises(ParseError):
        unwrap(f.sns(f.send(), sig="1"), TOPICS)


def test_raw_delivery_accepted():
    assert unwrap(json.dumps(f.send()), TOPICS)["eventType"] == "Send"


def test_normalize_extracts_fields():
    ev = normalize(f.bounce(subject="Reset your password", rcpts=("a@x.com", "b@x.com")))
    assert ev.event_type == "bounce" and ev.recipients == ["a@x.com", "b@x.com"]
    assert ev.region == "ap-south-1" and ev.aws_account_id == "111122223333"
    assert ev.from_addr == "support@example.com" and ev.from_domain == "example.com"
    assert ev.config_set == "mc-default" and ev.detail["bounceType"] == "Permanent"


def test_legacy_notification_type_supported():
    e = f.delivery()
    e["notificationType"] = e.pop("eventType")
    assert normalize(e).event_type == "delivery"


def test_unknown_event_type_rejected():
    with pytest.raises(ParseError):
        normalize({"eventType": "Weird", "mail": f.mail()})


def test_happy_path_timeline_and_state():
    for e in (f.send(), f.delivery()):
        process_body(f.sns(e), TOPICS)
    m = Message.objects.get()
    assert m.final_state == "delivery" and m.events.count() == 2
    assert m.source_app == "webapp" and m.sent_at.isoformat().startswith("2026-10-20T10:00:00")


def test_duplicate_delivery_is_idempotent():
    body = f.sns(f.delivery())
    assert process_body(body, TOPICS) == 1
    assert process_body(body, TOPICS) == 0
    assert MessageEvent.objects.count() == 1


def test_out_of_order_terminal_state_wins():
    # Bounce arrives first, then a late 'Send' and a 'Delivery' from a retry: bounce must stay terminal.
    for e in (f.bounce(), f.send(), f.delivery(), f.delay()):
        process_body(f.sns(e), TOPICS)
    assert Message.objects.get().final_state == "bounce"
    assert MessageRecipient.objects.get().state == "bounce"


def test_complaint_after_delivery_wins():
    for e in (f.send(), f.delivery(), f.complaint()):
        process_body(f.sns(e), TOPICS)
    assert Message.objects.get().final_state == "complaint"


def test_multi_recipient_message_state_is_worst_recipient():
    r = ("a@x.com", "b@x.com")
    process_body(f.sns(f.send(dest=r)), TOPICS)
    process_body(f.sns(f.delivery(rcpts=("a@x.com",), dest=r)), TOPICS)
    process_body(f.sns(f.bounce(rcpts=("b@x.com",), dest=r)), TOPICS)
    states = dict(MessageRecipient.objects.values_list("address_lower", "state"))
    assert states == {"a@x.com": "delivery", "b@x.com": "bounce"}
    assert Message.objects.get().final_state == "bounce"


def test_annotations_never_change_state():
    assert stronger("delivery", "open") == "delivery"
    assert stronger("send", "click") == "send"
    assert stronger("bounce", "delivery") == "bounce"


def test_recipient_address_matching_is_case_insensitive_but_preserves_case():
    process_body(f.sns(f.send(dest=("Alice@Example.com",))), TOPICS)
    process_body(f.sns(f.delivery(rcpts=("alice@example.com",), dest=("Alice@Example.com",))), TOPICS)
    r = MessageRecipient.objects.get()
    assert r.address == "Alice@Example.com" and r.state == "delivery"
