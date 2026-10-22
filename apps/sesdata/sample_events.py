"""Realistic SES event-publishing payloads (shapes taken from the AWS developer guide), used by tests and the demo seed."""
import json

TOPIC = "arn:aws:sns:ap-south-1:111122223333:mc-ses-events"


def mail(mid="0100018abc-1111", ts="2026-10-20T10:00:00.000Z", dest=("alice@example.com",), subject="Welcome", cfg="mc-default", tags=None):
    base_tags = {"ses:configuration-set": [cfg], "ses:from-domain": ["example.com"], "mc-app": ["webapp"]}
    base_tags.update(tags or {})
    return {
        "timestamp": ts, "messageId": mid, "source": "Acme <support@example.com>",
        "sourceArn": "arn:aws:ses:ap-south-1:111122223333:identity/example.com", "sendingAccountId": "111122223333",
        "destination": list(dest), "headersTruncated": False,
        "commonHeaders": {"from": ["Acme <support@example.com>"], "to": list(dest), "subject": subject},
        "tags": base_tags,
    }


def send(**kw):
    return {"eventType": "Send", "mail": mail(**kw), "send": {}}


def delivery(ts="2026-10-20T10:00:03.000Z", rcpts=("alice@example.com",), **kw):
    return {"eventType": "Delivery", "mail": mail(**{"dest": rcpts, **kw}),
            "delivery": {"timestamp": ts, "processingTimeMillis": 3000, "recipients": list(rcpts), "smtpResponse": "250 2.0.0 OK", "reportingMTA": "a1.smtp-out.amazonses.com"}}


def bounce(ts="2026-10-20T10:00:05.000Z", btype="Permanent", sub="General", rcpts=("alice@example.com",), feedback="fb-1", **kw):
    return {"eventType": "Bounce", "mail": mail(**{"dest": rcpts, **kw}),
            "bounce": {"bounceType": btype, "bounceSubType": sub, "timestamp": ts, "feedbackId": feedback,
                       "bouncedRecipients": [{"emailAddress": r, "action": "failed", "status": "5.1.1", "diagnosticCode": "smtp; 550 5.1.1 user unknown"} for r in rcpts]}}


def complaint(ts="2026-10-20T11:00:00.000Z", rcpts=("alice@example.com",), **kw):
    return {"eventType": "Complaint", "mail": mail(**{"dest": rcpts, **kw}),
            "complaint": {"timestamp": ts, "feedbackId": "cf-1", "complaintFeedbackType": "abuse",
                          "complainedRecipients": [{"emailAddress": r} for r in rcpts]}}


def delay(ts="2026-10-20T10:01:00.000Z", **kw):
    return {"eventType": "DeliveryDelay", "mail": mail(**kw),
            "deliveryDelay": {"timestamp": ts, "delayType": "MailboxFull", "expirationTime": "2026-10-20T16:00:00.000Z",
                              "delayedRecipients": [{"emailAddress": "alice@example.com", "status": "4.2.2", "diagnosticCode": "smtp; 452 mailbox full"}]}}


def sns(event, topic=TOPIC, sig="2"):
    return json.dumps({"Type": "Notification", "MessageId": "sns-1", "TopicArn": topic, "Message": json.dumps(event),
                       "Timestamp": "2026-10-20T10:00:06.000Z", "SignatureVersion": sig})
