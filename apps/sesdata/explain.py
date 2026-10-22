"""Plain-English explanations for SES bounce/complaint/delay events."""

BOUNCE = {
    ("Permanent", "General"): ("The receiving server rejected the address permanently.", "Check the address for typos; do not retry. SES adds it to the suppression list."),
    ("Permanent", "NoEmail"): ("The address does not exist.", "Ask the customer for a correct address."),
    ("Permanent", "Suppressed"): ("SES's global suppression list blocked this address.", "Request removal only if you are sure the address is valid."),
    ("Permanent", "OnAccountSuppressionList"): ("This address is on YOUR account suppression list from an earlier bounce/complaint.", "If the address is now valid, remove it from the suppression list (audited), then resend."),
    ("Permanent", "OnTenantSuppressionList"): ("This address is on the tenant-level suppression list.", "Remove it from the tenant suppression list if valid."),
    ("Permanent", "EmailValidationSuppressed"): ("SES email validation flagged the address as undeliverable.", "Verify the address with the customer."),
    ("Transient", "General"): ("A temporary delivery problem persisted until SES gave up.", "Retry later; contact the recipient's admin if repeated."),
    ("Transient", "MailboxFull"): ("The recipient's mailbox is full.", "Ask the recipient to free space, then resend."),
    ("Transient", "MessageTooLarge"): ("The message exceeded the recipient server's size limit.", "Send a smaller message or a link."),
    ("Transient", "ContentRejected"): ("The recipient server rejected the content (spam/policy filter).", "Review content, links, DKIM/SPF/DMARC alignment."),
    ("Transient", "AttachmentRejected"): ("The recipient server rejected an attachment.", "Remove or change the attachment type."),
    ("Undetermined", "Undetermined"): ("SES could not determine the bounce reason.", "Read the diagnostic code; check recipient domain DNS."),
}

COMPLAINT = ("The recipient marked this message as spam (or the provider reported a complaint).",
             "The address is auto-suppressed. Review what was sent; repeated complaints put the account at risk (0.1% review, 0.5% pause).")

DELAY = {
    "InternalFailure": "An internal SES problem delayed delivery; SES keeps retrying.",
    "General": "Delivery is delayed for an unspecified reason; SES keeps retrying.",
    "MailboxFull": "The recipient's mailbox is full; SES keeps retrying.",
    "SpamDetected": "The recipient server suspects spam; SES keeps retrying.",
    "RecipientServerError": "The recipient server had a problem; SES keeps retrying.",
    "IPFailure": "The recipient server temporarily blocked our sending IP; SES keeps retrying.",
    "TransientCommunicationFailure": "A temporary network problem; SES keeps retrying.",
    "BYOIPHostNameLookupUnavailable": "Hostname lookup unavailable for the BYO IP; SES keeps retrying.",
    "Undetermined": "Delayed for an undetermined reason; SES keeps retrying.",
    "SendingDeferral": "SES deferred sending to protect reputation; SES keeps retrying.",
}


def explain(event_type, detail):
    """Return (what_happened, what_to_do) for a stored event."""
    if event_type == "bounce":
        key = (detail.get("bounceType") or "Undetermined", detail.get("bounceSubType") or "Undetermined")
        return BOUNCE.get(key, ("SES reported a bounce.", "Read the diagnostic code below."))
    if event_type == "complaint":
        return COMPLAINT
    if event_type == "deliverydelay":
        return (DELAY.get(detail.get("delayType"), "Delivery is delayed; SES keeps retrying."), "No action unless it persists beyond the expiration time.")
    if event_type == "reject":
        return ("SES rejected the message before sending (e.g. virus detected).", "Inspect the content/attachment and resend a clean message.")
    if event_type == "renderingfailure":
        return ("A template failed to render.", "Fix the template variables or the template itself.")
    return ("", "")
