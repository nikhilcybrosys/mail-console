from django.conf import settings
from django.db import models


class SenderAddress(models.Model):
    """An address Compose may send as. Rows exist only for addresses in MC_SEND_FROM_ADDRESSES, and none is usable until a
    security admin enables it. The AWS send role has its own list: this table can never grant more than that."""

    address = models.CharField(max_length=254, unique=True)  # lowercase
    display_name = models.CharField(max_length=60, blank=True)
    reply_to = models.CharField(max_length=254, blank=True)
    enabled = models.BooleanField(default=False)
    # Optional ceiling on recipients per rolling 24 hours for this From address, for everyone together (on top of the
    # per-person and everyone limits). Null = no limit of its own.
    daily_limit = models.PositiveIntegerField(null=True, blank=True)
    updated_by = models.CharField(max_length=254, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["address"]


class Draft(models.Model):
    """A message being written, private to its author. Recipient fields are kept as typed and parsed when checked."""

    DRAFT, SENDING, UNKNOWN = "draft", "sending", "unknown"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="drafts")
    from_address = models.CharField(max_length=254, blank=True)
    to_text = models.TextField(blank=True)
    cc_text = models.TextField(blank=True)
    bcc_text = models.TextField(blank=True)
    subject = models.CharField(max_length=500, blank=True)
    body = models.TextField(blank=True)
    # draft: editable. sending: a send is in progress. unknown: the send call ended without a clear answer, so the mail
    # MAY have gone out; it must be checked in Sent mail before anyone sends it again.
    state = models.CharField(max_length=10, default=DRAFT)
    # Recipients reserved against the limits while a send is in flight or its outcome is unknown, so two sends at once
    # cannot both pass a limit that only one of them fits under. Cleared when the draft returns to a plain draft.
    reserved = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-updated_at"]


class SentMail(models.Model):
    """What was sent through Compose, by whom. The text of the message is kept only when MC_SEND_KEEP_BODY_DAYS is above 0, and is
    blanked (the rest of the row stays) once it is older than that. Only the plain text the author wrote is kept, never what the
    recipient received, and only mail sent through Compose: SES does not hand the console anyone else's content."""

    user_email = models.CharField(max_length=254, db_index=True)
    from_address = models.CharField(max_length=254)
    to_addrs = models.JSONField(default=list)
    cc_addrs = models.JSONField(default=list)
    bcc_addrs = models.JSONField(default=list)
    subject = models.CharField(max_length=500)
    recipient_count = models.PositiveIntegerField()
    reply_to = models.CharField(max_length=254, blank=True)
    body = models.TextField(blank=True)
    ses_message_id = models.CharField(max_length=100, db_index=True)
    sent_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-sent_at"]


class MessageTemplate(models.Model):
    """A reusable message with {{placeholders}}, shared by everyone who can compose. Using one only creates an ordinary
    draft; a template can never send anything by itself."""

    name = models.CharField(max_length=80)
    name_lower = models.CharField(max_length=80, unique=True)
    from_address = models.CharField(max_length=254, blank=True)  # optional default; must still be switched on to be used
    subject = models.CharField(max_length=500, blank=True)
    body = models.TextField(blank=True)
    created_by = models.CharField(max_length=254)
    updated_by = models.CharField(max_length=254)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name_lower"]
