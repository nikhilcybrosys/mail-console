from django.conf import settings
from django.db import models


class ApprovalRequest(models.Model):
    PENDING, APPROVED, REJECTED, EXECUTED, FAILED, EXPIRED = "pending", "approved", "rejected", "executed", "failed", "expired"

    action = models.CharField(max_length=60, db_index=True)
    params = models.JSONField(default=dict)
    params_hash = models.CharField(max_length=64)  # frozen at request time; re-checked before execution
    region = models.CharField(max_length=30)
    reason = models.TextField()
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="requested_approvals")
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="decided_approvals")
    state = models.CharField(max_length=12, default=PENDING, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    decided_at = models.DateTimeField(null=True, blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
