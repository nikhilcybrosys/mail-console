from django.db import models


class AwsAccount(models.Model):
    """A registered AWS account the console watches (v1: exactly one)."""

    alias = models.CharField(max_length=100, unique=True)
    aws_account_id = models.CharField(max_length=12, unique=True)
    role_arn = models.CharField(max_length=300, blank=True)  # cross-account read role (later)
    enabled = models.BooleanField(default=True)


class MailCategory(models.Model):
    """Decides which mail may keep its body, for how long, and what is redacted."""

    name = models.CharField(max_length=100, unique=True)
    config_set = models.CharField(max_length=100, blank=True)
    store_body = models.BooleanField(default=False)
    body_retention_days = models.PositiveIntegerField(default=30)
    redaction_rules = models.JSONField(default=list, blank=True)  # list of regex strings

    def __str__(self):
        return self.name


class Message(models.Model):
    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    ses_message_id = models.CharField(max_length=100)
    from_addr = models.CharField(max_length=320, blank=True)
    from_domain = models.CharField(max_length=255, blank=True, db_index=True)
    subject = models.CharField(max_length=998, blank=True)
    config_set = models.CharField(max_length=100, blank=True, db_index=True)
    tags = models.JSONField(default=dict, blank=True)
    source_app = models.CharField(max_length=100, blank=True, db_index=True)
    mail_category = models.CharField(max_length=100, blank=True, db_index=True)
    sent_at = models.DateTimeField(db_index=True)
    final_state = models.CharField(max_length=20, default="send", db_index=True)
    final_state_at = models.DateTimeField(null=True, blank=True)
    body_ref = models.CharField(max_length=500, blank=True)  # S3 key / archive id, opted-in only

    class Meta:
        constraints = [models.UniqueConstraint(fields=["aws_account_id", "region", "ses_message_id"], name="uniq_ses_message")]
        indexes = [models.Index(fields=["-sent_at"])]


class MessageRecipient(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="recipients")
    address = models.CharField(max_length=320)
    address_lower = models.CharField(max_length=320)
    state = models.CharField(max_length=20, default="send")
    last_event_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["message", "address_lower"], name="uniq_msg_recipient")]
        indexes = [models.Index(fields=["address_lower", "-last_event_at"])]


class MessageEvent(models.Model):
    # NOTE: monthly partitioning is deferred (see docs/DEVIATIONS.md); indexes cover v1 volumes.
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="events")
    recipient = models.CharField(max_length=320, blank=True)
    event_type = models.CharField(max_length=30, db_index=True)
    event_ts = models.DateTimeField(db_index=True)
    payload = models.JSONField()
    idempotency_key = models.CharField(max_length=64, unique=True)
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["event_ts", "id"]


class SuppressionEntry(models.Model):
    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    address = models.CharField(max_length=320)  # exact case, SES keys are case-sensitive
    address_lower = models.CharField(max_length=320, db_index=True)
    reason = models.CharField(max_length=20)  # BOUNCE | COMPLAINT
    last_update_time = models.DateTimeField(null=True, blank=True)
    source = models.CharField(max_length=20, default="SES")
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["aws_account_id", "region", "address"], name="uniq_suppression")]


class SuppressionChange(models.Model):
    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    address = models.CharField(max_length=320)
    change = models.CharField(max_length=20)  # removed | added | seen_removed | seen_added
    reason = models.CharField(max_length=20, blank=True)
    actor = models.CharField(max_length=254, blank=True)
    at = models.DateTimeField(auto_now_add=True)


class AccountSnapshot(models.Model):
    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    taken_at = models.DateTimeField(auto_now_add=True, db_index=True)
    production_access = models.BooleanField(default=False)
    sending_enabled = models.BooleanField(default=False)
    enforcement_status = models.CharField(max_length=40, blank=True)
    max_24h_send = models.FloatField(default=0)
    sent_last_24h = models.FloatField(default=0)
    max_send_rate = models.FloatField(default=0)
    raw = models.JSONField(default=dict)


class IdentitySnapshot(models.Model):
    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    identity = models.CharField(max_length=320)
    identity_type = models.CharField(max_length=30, blank=True)
    taken_at = models.DateTimeField(auto_now_add=True, db_index=True)
    verified = models.BooleanField(default=False)
    dkim_status = models.CharField(max_length=30, blank=True)
    dkim_tokens = models.JSONField(default=list)
    dkim_signing_origin = models.CharField(max_length=30, blank=True)
    mail_from_domain = models.CharField(max_length=255, blank=True)
    mail_from_status = models.CharField(max_length=30, blank=True)
    default_config_set = models.CharField(max_length=100, blank=True)
    raw = models.JSONField(default=dict)


class DnsCheckResult(models.Model):
    domain = models.CharField(max_length=255, db_index=True)
    record_kind = models.CharField(max_length=30)  # dkim | spf | dmarc | mail_from_mx | mail_from_spf
    ok = models.BooleanField()
    expected = models.JSONField(default=list)
    actual = models.JSONField(default=list)
    detail = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField(auto_now_add=True, db_index=True)


class ConfigSetSnapshot(models.Model):
    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    name = models.CharField(max_length=100)
    taken_at = models.DateTimeField(auto_now_add=True, db_index=True)
    destinations = models.JSONField(default=list)
    sending_enabled = models.BooleanField(default=True)
    tracking_domain = models.CharField(max_length=255, blank=True)
    archive_arn = models.CharField(max_length=300, blank=True)
    raw = models.JSONField(default=dict)


class Alert(models.Model):
    key = models.CharField(max_length=100, db_index=True)  # dedupe key, e.g. "bounce_rate:ap-south-1"
    severity = models.CharField(max_length=10)  # warn | page
    title = models.CharField(max_length=200)
    detail = models.TextField(blank=True)
    opened_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    notified_at = models.DateTimeField(null=True, blank=True)  # set once every configured channel has the "firing" notice
    notified_channels = models.JSONField(default=list, blank=True)  # channels that already have it (a failed one is retried alone)
    resolved_notified_at = models.DateTimeField(null=True, blank=True)


class BodyAccessLog(models.Model):
    """Every time someone opens a stored message body (reason is mandatory)."""

    user_email = models.CharField(max_length=254, db_index=True)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="body_accesses", null=True, blank=True)
    inbound_id = models.BigIntegerField(null=True, blank=True)
    reason = models.TextField()
    at = models.DateTimeField(auto_now_add=True, db_index=True)


class ArchiveSyncItem(models.Model):
    """One archived message and what happened when it was copied into the mailbox. Metadata only: never the message itself.

    `archived_message_id` is unique, which makes a repeated run harmless: nothing is imported twice."""

    IMPORTED, FAILED, SKIPPED = "imported", "failed", "skipped"

    archived_message_id = models.CharField(max_length=300, unique=True)
    message_id_header = models.CharField(max_length=300, blank=True)
    from_addr = models.CharField(max_length=320, blank=True)
    state = models.CharField(max_length=10, db_index=True)  # imported | failed | skipped
    attempts = models.PositiveSmallIntegerField(default=0)
    detail = models.CharField(max_length=200, blank=True)   # a short reason for failed/skipped; never mail content or API error text
    gmail_id = models.CharField(max_length=100, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    done_at = models.DateTimeField(null=True, blank=True)


class ArchiveSyncState(models.Model):
    """One row: how far the scan of the archive has got, and when the sync last ran."""

    scanned_to = models.DateTimeField(null=True, blank=True)   # every window before this was fully processed
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_ok_at = models.DateTimeField(null=True, blank=True)   # last run that finished without a failure
    incomplete_at = models.DateTimeField(null=True, blank=True)    # last time a window held more messages than a search can return
    incomplete_windows = models.PositiveIntegerField(default=0)    # how many such windows there have been in all
