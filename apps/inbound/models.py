from django.db import models


class InboundMessage(models.Model):
    """Metadata mirror of a Mail Manager archive message (body stays in the archive/S3)."""

    aws_account_id = models.CharField(max_length=12)
    region = models.CharField(max_length=30)
    archive_message_id = models.CharField(max_length=200)
    received_at = models.DateTimeField(db_index=True)
    from_addr = models.CharField(max_length=320, blank=True)
    to_addrs = models.JSONField(default=list)
    subject = models.CharField(max_length=998, blank=True)
    message_id_header = models.CharField(max_length=500, blank=True, db_index=True)
    in_reply_to = models.CharField(max_length=500, blank=True)
    references = models.TextField(blank=True)
    thread_key = models.CharField(max_length=500, blank=True, db_index=True)
    verdicts = models.JSONField(default=dict)  # spf/dkim/dmarc/spam/virus
    size = models.PositiveIntegerField(default=0)
    has_attachments = models.BooleanField(default=False)
    kind = models.CharField(max_length=20, default="mail", db_index=True)  # mail | bounce | dmarc_report
    s3_ref = models.CharField(max_length=500, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["aws_account_id", "region", "archive_message_id"], name="uniq_inbound")]
        ordering = ["-received_at"]


class InboundAttachment(models.Model):
    message = models.ForeignKey(InboundMessage, on_delete=models.CASCADE, related_name="attachments")
    index = models.PositiveIntegerField()
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=200)
    size = models.PositiveIntegerField(default=0)
    s3_key = models.CharField(max_length=500, blank=True)
    scan_state = models.CharField(max_length=20, default="pending")  # pending | clean | infected | failed

    class Meta:
        constraints = [models.UniqueConstraint(fields=["message", "index"], name="uniq_attachment")]


class DmarcReport(models.Model):
    # A report either came from the inbox (message set) or was uploaded by a person (message empty, uploaded_by set).
    message = models.ForeignKey(InboundMessage, on_delete=models.CASCADE, related_name="dmarc_reports", null=True, blank=True)
    # "inbox": received by mail from a sender on the operator's list of reporting providers (the sender was authenticated by SES's
    # DMARC check). "mail": received by mail from an authenticated sender that is NOT on that list (the identity of the reporter is
    # unchecked). "upload": added by hand. The last two are taken at face value; the sha256 of the original file lets anyone
    # compare it with the attachment later.
    source = models.CharField(max_length=10, default="inbox")
    sender_domain = models.CharField(max_length=255, blank=True)  # for mailed reports: the authenticated From domain; part of the uniqueness key
    file_sha256 = models.CharField(max_length=64, blank=True)
    uploaded_by = models.CharField(max_length=254, blank=True)
    uploaded_at = models.DateTimeField(null=True, blank=True)
    org_name = models.CharField(max_length=200)
    report_id = models.CharField(max_length=200)
    domain = models.CharField(max_length=255, db_index=True)
    begin = models.DateTimeField()
    end = models.DateTimeField()
    policy = models.CharField(max_length=20, blank=True)
    rows = models.JSONField(default=list)  # [{source_ip,count,disposition,dkim,spf,header_from}]
    pass_count = models.PositiveIntegerField(default=0)
    fail_count = models.PositiveIntegerField(default=0)

    class Meta:
        # Per source AND sender, so neither an uploaded report nor a forged mailed one (another sender claiming the same reporter name
        # and id) can occupy the slot of the genuine report.
        constraints = [models.UniqueConstraint(fields=["source", "sender_domain", "org_name", "report_id"], name="uniq_dmarc_report")]


class DmarcMail(models.Model):
    """One line per mail that arrived at the reports address: what happened to it. Not the mail itself (that is in S3 for a few days).

    `ses_message_id` is unique, which makes a redelivered queue message harmless. Rows are pruned after 90 days.
    """

    ses_message_id = models.CharField(max_length=200, unique=True)
    received_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    from_addr = models.CharField(max_length=320, blank=True)
    # The From domain, but ONLY once SES's DMARC check passed (before that the From is unauthenticated and could name anyone,
    # so it must not count against anyone's allowance). Blank for mail that failed the notification checks.
    sender_domain = models.CharField(max_length=255, blank=True, db_index=True)
    outcome = models.CharField(max_length=10)  # accepted | duplicate | refused
    reason = models.CharField(max_length=300, blank=True)
    reports = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["-received_at"]
