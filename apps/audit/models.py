from django.db import models


class AuditLog(models.Model):
    """Append-only, hash-chained audit trail.

    Tamper resistance, in layers:
    1. App: `record()` is the only writer; save() on an existing row and delete() raise.
    2. DB: a trigger (migration 0002) rejects UPDATE, DELETE and TRUNCATE for every role.
    3. Chain: each row stores sha256(prev_hash + canonical fields); `verify_chain()` detects edits.
    4. Off-box: `export_audit` streams rows to an S3 bucket with Object Lock (compliance mode).
    """

    ts = models.DateTimeField(db_index=True)
    actor = models.CharField(max_length=254, db_index=True)  # email or "system"
    action = models.CharField(max_length=100, db_index=True)
    target = models.CharField(max_length=500, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    request_id = models.CharField(max_length=64, blank=True)
    details = models.JSONField(default=dict)
    prev_hash = models.CharField(max_length=64)
    row_hash = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ["id"]

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise PermissionError("Audit rows are immutable")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("Audit rows are immutable")


class AuditExportCursor(models.Model):
    """Single row: highest AuditLog id already streamed to the Object Lock bucket.

    Kept separate so AuditLog rows themselves never need an UPDATE.
    """

    last_exported_id = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
