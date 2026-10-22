from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.models import User
from apps.approvals import service
from apps.approvals.models import ApprovalRequest
from apps.audit.models import AuditLog
from apps.core.rbac import CAPABILITIES, DELIVERABILITY_ADMIN, ROLES, SECURITY_ADMIN, SUPPORT, VIEWER, has_capability
from apps.sesdata import aws

pytestmark = pytest.mark.django_db


class FakeWriter:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def rec(*a, **k):
            self.calls.append((name, a, k))
        return rec


@pytest.fixture
def fake(monkeypatch):
    w = FakeWriter()
    seen = {}

    def fake_assume(region, tier, email, rid):
        seen.update(region=region, tier=tier, email=email)
        return w
    monkeypatch.setattr(aws, "assume_writer", fake_assume)
    w.seen = seen
    return w


def mk(email, role):
    return User.objects.create_user(email, role=role)


def test_rbac_matrix_viewer_is_read_only():
    v = mk("v@example.com", VIEWER)
    for cap in CAPABILITIES:
        assert has_capability(v, cap) == (cap == "view_metadata"), cap


def test_rbac_unknown_capability_fails_loud():
    with pytest.raises(KeyError):
        has_capability(mk("s@example.com", SUPPORT), "typo_capability")


def test_inactive_user_has_nothing():
    u = mk("x@example.com", SECURITY_ADMIN)
    u.is_active = False
    assert not has_capability(u, "view_metadata")


def test_break_glass_expiry():
    u = mk("bg@example.com", VIEWER)
    u.break_glass_role, u.break_glass_until = SECURITY_ADMIN, timezone.now() + timedelta(minutes=30)
    assert has_capability(u, "identity_write")
    u.break_glass_until = timezone.now() - timedelta(seconds=1)
    assert not has_capability(u, "identity_write")


def test_support_single_removal_executes_directly_with_source_identity(fake):
    u = mk("sup@example.com", SUPPORT)
    req = service.request_action(u, "suppression.remove", {"addresses": ["a@x.com"]}, "ap-south-1", "customer confirmed address")
    assert req.state == ApprovalRequest.EXECUTED
    assert fake.calls == [("delete_suppressed", ("a@x.com",), {})]
    assert fake.seen == {"region": "ap-south-1", "tier": "ops", "email": "sup@example.com"}


def test_support_cannot_bulk_remove(fake):
    u = mk("sup@example.com", SUPPORT)
    with pytest.raises(service.ApprovalError):
        service.request_action(u, "suppression.remove", {"addresses": ["a@x.com", "b@x.com"]}, "ap-south-1", "r")
    assert fake.calls == []


def test_reason_is_mandatory(fake):
    u = mk("sup@example.com", SUPPORT)
    with pytest.raises(service.ApprovalError):
        service.request_action(u, "suppression.remove", {"addresses": ["a@x.com"]}, "ap-south-1", "  ")


def test_bulk_over_threshold_needs_second_person(fake):
    req_user, approver = mk("d@example.com", DELIVERABILITY_ADMIN), mk("s@example.com", SECURITY_ADMIN)
    addrs = [f"u{i}@x.com" for i in range(51)]
    req = service.request_action(req_user, "suppression.remove", {"addresses": addrs}, "ap-south-1", "cleanup after incident")
    assert req.state == ApprovalRequest.PENDING and fake.calls == []
    with pytest.raises(service.ApprovalError):
        service.decide(req.pk, req_user, True)  # self-approval
    service.decide(req.pk, approver, True)
    done = service.execute(req, approver)
    assert done.state == ApprovalRequest.EXECUTED and len(fake.calls) == 51
    assert fake.seen["email"] == "d@example.com"  # CloudTrail attributes to the requester


def test_identity_delete_always_needs_approval_and_security_role(fake):
    sup, sec, sec2 = mk("s@example.com", SUPPORT), mk("a@example.com", SECURITY_ADMIN), mk("b@example.com", SECURITY_ADMIN)
    with pytest.raises(service.ApprovalError):
        service.request_action(sup, "identity.delete", {"identity": "example.com"}, "ap-south-1", "r")
    req = service.request_action(sec, "identity.delete", {"identity": "old.example.com"}, "ap-south-1", "decommission")
    assert req.state == ApprovalRequest.PENDING
    with pytest.raises(service.ApprovalError):
        service.execute(req, sec)  # cannot execute unapproved
    service.decide(req.pk, sec2, True)
    assert service.execute(req, sec2).state == ApprovalRequest.EXECUTED
    assert fake.seen["tier"] == "security"


def test_viewer_cannot_approve(fake):
    sec, v = mk("a@example.com", SECURITY_ADMIN), mk("v@example.com", VIEWER)
    req = service.request_action(sec, "account.sending", {"enabled": False}, "ap-south-1", "incident pause")
    with pytest.raises(service.ApprovalError):
        service.decide(req.pk, v, True)


def test_expired_request_cannot_be_approved_or_run(fake):
    sec, sec2 = mk("a@example.com", SECURITY_ADMIN), mk("b@example.com", SECURITY_ADMIN)
    req = service.request_action(sec, "account.sending", {"enabled": False}, "ap-south-1", "r")
    ApprovalRequest.objects.filter(pk=req.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
    with pytest.raises(service.ApprovalError):
        service.decide(req.pk, sec2, True)
    assert fake.calls == []


def test_param_tampering_after_approval_is_blocked(fake):
    sec, sec2 = mk("a@example.com", SECURITY_ADMIN), mk("b@example.com", SECURITY_ADMIN)
    req = service.request_action(sec, "identity.delete", {"identity": "old.example.com"}, "ap-south-1", "r")
    service.decide(req.pk, sec2, True)
    ApprovalRequest.objects.filter(pk=req.pk).update(params={"identity": "example.com"})  # attacker edits the DB row
    with pytest.raises(service.ApprovalError):
        service.execute(req, sec2)
    assert fake.calls == []
    assert AuditLog.objects.filter(action="approval.tamper_detected").exists()


def test_executed_request_cannot_run_twice(fake):
    sec, sec2 = mk("a@example.com", SECURITY_ADMIN), mk("b@example.com", SECURITY_ADMIN)
    req = service.request_action(sec, "account.sending", {"enabled": True}, "ap-south-1", "resume")
    service.decide(req.pk, sec2, True)
    service.execute(req, sec2)
    with pytest.raises(service.ApprovalError):
        service.execute(req, sec2)
    assert len(fake.calls) == 1


def test_aws_failure_is_recorded_not_raised(monkeypatch):
    class Boom:
        def delete_suppressed(self, a):
            raise RuntimeError("AccessDenied: nope")
    monkeypatch.setattr(aws, "assume_writer", lambda *a: Boom())
    u = mk("sup@example.com", SUPPORT)
    req = service.request_action(u, "suppression.remove", {"addresses": ["a@x.com"]}, "ap-south-1", "r")
    assert req.state == ApprovalRequest.FAILED and "AccessDenied" in req.result["error"]


def test_request_is_attributed_to_the_requester_even_without_a_web_request(fake):
    sec = mk("a@example.com", SECURITY_ADMIN)
    service.request_action(sec, "account.sending", {"enabled": False}, "ap-south-1", "incident drill")
    assert AuditLog.objects.get(action="approval.requested").actor == "a@example.com"
