"""Four-eyes approvals for risky SES writes.

Invariants (all covered by tests):
- approver != requester, approver needs the `approve` capability, request not expired;
- params are hashed at request time and re-verified before execution (DB-row tampering is caught);
- execution happens once, through a write role assumed with SourceIdentity = requester;
- every state change is audited.
"""
import hashlib
import json
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.audit.service import record
from apps.core.rbac import has_capability
from apps.sesdata import aws

from .models import ApprovalRequest


class ApprovalError(Exception):
    pass


def _hash(action, params, region):
    return hashlib.sha256(json.dumps([action, params, region], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# action -> (capability needed to REQUEST, write tier, always_needs_approval, executor)
def _x_suppress_remove(w, p):
    for a in p["addresses"]:
        w.delete_suppressed(a)


def _x_suppress_add(w, p):
    for a in p["addresses"]:
        w.put_suppressed(a, p["reason"])


def _x_identity_delete(w, p):
    w.delete_identity(p["identity"])


def _x_dkim(w, p):
    w.put_dkim_attributes(p["identity"], p["signing_enabled"])


def _x_mail_from(w, p):
    w.put_mail_from(p["identity"], p["domain"], p.get("behavior", "USE_DEFAULT_VALUE"))


def _x_account_sending(w, p):
    w.put_account_sending(p["enabled"])


def _x_account_suppression(w, p):
    w.put_account_suppression(p["reasons"])


def _x_event_dest(w, p):
    op = p["op"]
    if op == "create":
        w.create_event_destination(p["config_set"], p["name"], p["definition"])
    elif op == "update":
        w.update_event_destination(p["config_set"], p["name"], p["definition"])
    elif op == "delete":
        w.delete_event_destination(p["config_set"], p["name"])
    else:
        raise ApprovalError(f"bad op {op!r}")


ACTIONS = {
    "suppression.remove": ("suppression_remove_single", "ops", False, _x_suppress_remove),
    "suppression.add": ("suppression_bulk", "ops", False, _x_suppress_add),
    "identity.delete": ("identity_write", "security", True, _x_identity_delete),
    "identity.dkim": ("identity_write", "security", True, _x_dkim),
    "identity.mail_from": ("identity_write", "security", True, _x_mail_from),
    "account.sending": ("account_attrs_write", "security", True, _x_account_sending),
    "account.suppression": ("account_attrs_write", "security", True, _x_account_suppression),
    "event_destination.change": ("event_destination_write", "security", True, _x_event_dest),
}


def needs_approval(action, params):
    _, _, always, _ = ACTIONS[action]
    if always:
        return True
    if action.startswith("suppression."):
        return len(params.get("addresses", [])) > settings.BULK_SUPPRESSION_APPROVAL_THRESHOLD
    return False


def request_action(user, action, params, region, reason, request=None):
    """Create a request. Returns the ApprovalRequest; executes immediately when no approval is needed."""
    if action not in ACTIONS:
        raise ApprovalError(f"unknown action {action!r}")
    cap = ACTIONS[action][0]
    if not has_capability(user, cap):
        raise ApprovalError("not permitted")
    if action == "suppression.remove" and not (1 <= len(params.get("addresses", [])) <= 10000):
        raise ApprovalError("addresses must contain 1..10000 entries")
    if action == "suppression.remove" and len(params["addresses"]) > 1 and not has_capability(user, "suppression_bulk"):
        raise ApprovalError("bulk removal needs deliverability_admin")
    if not reason or not reason.strip():
        raise ApprovalError("a reason is required")
    now = timezone.now()
    req = ApprovalRequest.objects.create(
        action=action, params=params, params_hash=_hash(action, params, region), region=region, reason=reason.strip(),
        requested_by=user, expires_at=now + timedelta(hours=settings.APPROVAL_TTL_HOURS))
    record("approval.requested", actor=user.email, target=f"{action}#{req.pk}", request=request, details={"action": action, "region": region, "count": len(params.get("addresses", [])) or None})
    if not needs_approval(action, params):
        return execute(req, user, request=request)
    return req


@transaction.atomic
def decide(req_id, approver, approve, request=None):
    req = ApprovalRequest.objects.select_for_update().get(pk=req_id)
    if req.state != ApprovalRequest.PENDING:
        raise ApprovalError(f"request is {req.state}")
    if req.expires_at <= timezone.now():
        req.state = ApprovalRequest.EXPIRED
        req.save(update_fields=["state"])
        record("approval.expired", target=f"{req.action}#{req.pk}", request=request)
        raise ApprovalError("request expired")
    if approver.pk == req.requested_by_id:
        raise ApprovalError("approver must differ from requester")
    if not has_capability(approver, "approve"):
        raise ApprovalError("not permitted to approve")
    req.approver = approver
    req.decided_at = timezone.now()
    req.state = ApprovalRequest.APPROVED if approve else ApprovalRequest.REJECTED
    req.save(update_fields=["approver", "decided_at", "state"])
    record("approval.approved" if approve else "approval.rejected", target=f"{req.action}#{req.pk}", request=request)
    return req


def execute(req, actor, request=None, writer=None):
    """Run an approved (or approval-free) request exactly once."""
    with transaction.atomic():
        req = ApprovalRequest.objects.select_for_update().get(pk=req.pk)
        direct = not needs_approval(req.action, req.params)
        if req.state == ApprovalRequest.PENDING and direct:
            pass
        elif req.state != ApprovalRequest.APPROVED:
            raise ApprovalError(f"cannot execute a {req.state} request")
        if req.expires_at <= timezone.now():
            raise ApprovalError("request expired")
        tampered = _hash(req.action, req.params, req.region) != req.params_hash
        if tampered:
            req.state = ApprovalRequest.FAILED
            req.result = {"error": "parameters changed after request"}
            req.save(update_fields=["state", "result"])
        else:
            _, tier, _, executor = ACTIONS[req.action]
            req.state = "executing"  # not terminal; protects against double-click inside the lock window
            req.save(update_fields=["state"])
    if tampered:
        # Recorded and raised AFTER the transaction commits, so the evidence is not rolled back.
        record("approval.tamper_detected", target=f"{req.action}#{req.pk}", request=request)
        raise ApprovalError("parameters changed after request")
    try:
        w = writer or aws.assume_writer(req.region, tier, req.requested_by.email, f"{req.pk}")
        executor(w, req.params)
        req.state, req.result = ApprovalRequest.EXECUTED, {"ok": True}
    except Exception as exc:  # AWS error details are safe to store; no secrets in them
        req.state, req.result = ApprovalRequest.FAILED, {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    req.executed_at = timezone.now()
    req.save(update_fields=["state", "result", "executed_at"])
    record(f"approval.{req.state}", actor=actor.email, target=f"{req.action}#{req.pk}", request=request,
           details={"region": req.region, "approved_by": req.approver.email if req.approver_id else None})
    return req
