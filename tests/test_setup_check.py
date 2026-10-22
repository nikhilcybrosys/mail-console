import json
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata import setupcheck
from apps.sesdata.ingest import process_body
from apps.sesdata.models import AccountSnapshot, ConfigSetSnapshot, IdentitySnapshot

from . import factories as f
from .test_views import login

pytestmark = pytest.mark.django_db
REG = "ap-south-1"
TOPIC = f.TOPIC
QUEUE = "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-events"


class FakeSqs:
    def __init__(self, **attrs):
        self.attrs = {"ApproximateNumberOfMessages": "0", "ApproximateNumberOfMessagesNotVisible": "0",
                      "RedrivePolicy": "{}", "SqsManagedSseEnabled": "true",
                      "Policy": json.dumps({"Statement": [{"Condition": {"ArnEquals": {"aws:SourceArn": TOPIC}}}]}), **attrs}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": self.attrs}


class BrokenSqs:
    def get_queue_attributes(self, **kw):
        err = Exception("boom: secret detail that must not be shown")
        err.response = {"Error": {"Code": "AccessDenied"}}
        raise err


def by_key(checks):
    return {c.key: c for c in checks}


def wire(settings, *, destination=True, identity_set="mc-set", types=("SEND", "DELIVERY", "BOUNCE", "COMPLAINT"), topic=TOPIC):
    settings.SQS_EVENTS_QUEUE_URL = QUEUE
    AccountSnapshot.objects.create(aws_account_id="1", region=REG, production_access=True, sending_enabled=True, enforcement_status="HEALTHY")
    IdentitySnapshot.objects.create(aws_account_id="1", region=REG, identity="example.com", identity_type="DOMAIN", verified=True,
                                    dkim_status="SUCCESS", default_config_set=identity_set)
    dests = [{"Name": "mc", "Enabled": True, "MatchingEventTypes": list(types), "SnsDestination": {"TopicArn": topic}}] if destination else []
    ConfigSetSnapshot.objects.create(aws_account_id="1", region=REG, name="mc-set", destinations=dests)


# ---------------------------------------------------------------- the checks themselves
def test_nothing_synced_yet_is_a_failure_with_a_fix(settings):
    settings.SQS_EVENTS_QUEUE_URL = QUEUE
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["sync"].status == setupcheck.FAIL and c["sync"].fix


def test_fully_wired_setup_has_no_failures_or_warnings_in_the_pipeline(settings):
    wire(settings)
    process_body(f.sns(f.send()), [TOPIC])
    checks = setupcheck.run_checks(REG, sqs_client=FakeSqs())
    pipe = [c for c in checks if c.group == "Event pipeline"]
    assert setupcheck.worst(pipe) == setupcheck.OK, [(c.key, c.status, c.detail) for c in pipe]
    assert by_key(checks)["sync"].status == setupcheck.OK and by_key(checks)["cover"].status == setupcheck.OK


def test_no_event_destination_is_a_failure(settings):
    wire(settings, destination=False)
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["dest"].status == setupcheck.FAIL and "event destination" in c["dest"].fix.lower()


def test_destination_to_a_topic_the_worker_would_refuse_is_a_failure(settings):
    wire(settings, topic="arn:aws:sns:ap-south-1:111122223333:other-topic")
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["dest"].status == setupcheck.FAIL and "refuse" in c["dest"].detail


def test_missing_essential_event_types_and_uncovered_identity_are_warned(settings):
    wire(settings, types=("SEND",), identity_set="")
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["types"].status == setupcheck.WARN and c["cover"].status == setupcheck.WARN


def test_stale_sync_and_sandbox_account_are_warned(settings):
    wire(settings)
    AccountSnapshot.objects.update(taken_at=timezone.now() - timedelta(hours=2), production_access=False)
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["sync"].status == setupcheck.WARN and c["prod"].status == setupcheck.WARN


def test_queue_problems_are_reported_without_leaking_aws_error_text(settings):
    wire(settings)
    c = by_key(setupcheck.run_checks(REG, sqs_client=BrokenSqs()))
    assert c["queue"].status == setupcheck.FAIL and "AccessDenied" in c["queue"].detail and "secret detail" not in c["queue"].detail
    s = FakeSqs()  # AWS omits attributes that are not set, so remove them rather than blanking them
    for k in ("RedrivePolicy", "SqsManagedSseEnabled", "Policy"):
        s.attrs.pop(k)
    c = by_key(setupcheck.run_checks(REG, sqs_client=s))
    assert c["dlq"].status == setupcheck.WARN and c["sse"].status == setupcheck.WARN and c["qpolicy"].status == setupcheck.FAIL


def test_unconfigured_queue_url_is_a_failure(settings):
    settings.SQS_EVENTS_QUEUE_URL = ""
    assert by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))["queue"].status == setupcheck.FAIL


def test_a_large_backlog_is_warned(settings):
    wire(settings)
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs(ApproximateNumberOfMessages="5000")))
    assert c["queue"].status == setupcheck.WARN


def test_no_events_ingested_yet_is_a_warning_with_instructions(settings):
    wire(settings)
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["arrived"].status == setupcheck.WARN and "Send one email" in c["arrived"].fix


def test_single_approver_is_warned_and_two_are_fine(settings):
    login(SECURITY_ADMIN, "one@example.com")
    assert by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))["four"].status == setupcheck.WARN
    login(DELIVERABILITY_ADMIN, "two@example.com")
    assert by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))["four"].status == setupcheck.OK


def test_hardening_flags_weak_secret_and_debug(settings):
    settings.DEBUG, settings.SECRET_KEY = True, "short-insecure-key"
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["debug"].status == setupcheck.FAIL and c["key"].status == setupcheck.FAIL


def test_viewer_off_is_a_note_not_a_problem(settings):
    settings.MAILVIEW_HOST = "viewer-disabled.invalid"
    assert by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))["viewer"].status == setupcheck.INFO


# ---------------------------------------------------------------- the active write-role test
def test_write_role_test_reports_each_role_and_hides_error_detail(settings):
    settings.AWS_WRITE_ROLE_OPS_ARN = "arn:aws:iam::111122223333:role/ops"
    settings.AWS_WRITE_ROLE_SECURITY_ARN = "arn:aws:iam::111122223333:role/security"
    calls = []

    def assume(region, tier, email, rid):
        calls.append((tier, email))
        if tier == "security":
            err = Exception("AccessDenied: user is not authorized to perform sts:AssumeRole with secret detail")
            err.response = {"Error": {"Code": "AccessDenied"}}
            raise err

    res = by_key(setupcheck.try_write_roles(REG, "ann@corp.example", "r1", assume=assume))
    assert calls == [("ops", "ann@corp.example"), ("security", "ann@corp.example")]
    assert res["ops"].status == setupcheck.OK and res["security"].status == setupcheck.FAIL
    assert "AccessDenied" in res["security"].detail and "secret detail" not in res["security"].detail


def test_write_role_test_skips_unconfigured_roles(settings):
    settings.AWS_WRITE_ROLE_OPS_ARN = settings.AWS_WRITE_ROLE_SECURITY_ARN = ""
    res = setupcheck.try_write_roles(REG, "ann@corp.example", "r1", assume=lambda *a: pytest.fail("must not be called"))
    assert [c.status for c in res] == [setupcheck.INFO, setupcheck.INFO]


# ---------------------------------------------------------------- the page and its permissions
def test_page_is_for_admins_only_and_anonymous_is_redirected():
    from django.test import Client
    assert Client(HTTP_HOST="console.test").get(reverse("setup_check")).status_code == 302
    for role in (VIEWER, SUPPORT):
        c, _ = login(role, f"{role}@example.com")
        assert c.get(reverse("setup_check")).status_code == 403, role
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    assert c.get(reverse("setup_check")).status_code == 200


def test_page_renders_and_appears_in_navigation(settings, monkeypatch):
    wire(settings)
    monkeypatch.setattr(setupcheck, "_queue_checks", lambda g, now, sqs: [])  # the page test must never call AWS
    c, _ = login(SECURITY_ADMIN, "s@example.com")
    html = c.get(reverse("setup_check")).content.decode()
    assert "Setup check" in html and "State sync is running" in html and reverse("setup_check") in html


def test_write_role_test_button_needs_step_up_and_is_audited(settings, monkeypatch):
    settings.AWS_WRITE_ROLE_OPS_ARN = "arn:aws:iam::111122223333:role/ops"
    seen = []
    monkeypatch.setattr("apps.sesdata.aws.assume_writer", lambda *a: seen.append(a))
    monkeypatch.setattr(setupcheck, "_queue_checks", lambda g, now, sqs: [])
    c, _ = login(SECURITY_ADMIN, "s@example.com")
    r = c.post(reverse("setup_test_write_roles"))
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up")) and not seen  # no passkey, nothing assumed
    c2, _ = login(SECURITY_ADMIN, "s2@example.com", step_up=True)
    r = c2.post(reverse("setup_test_write_roles"))
    assert r.status_code == 200 and seen and seen[0][1] == "ops" and seen[0][2] == "s2@example.com"
    assert b"The ops role can be assumed" in r.content
    assert AuditLog.objects.filter(action="setup.test_write_roles", actor="s2@example.com").exists()
    d, _ = login(DELIVERABILITY_ADMIN, "d@example.com", step_up=True)
    assert d.post(reverse("setup_test_write_roles")).status_code == 403  # only security admins may assume write roles


def test_scoped_user_only_sees_identities_in_their_scope(settings):
    """The page must not leak identity names a scoped user cannot see on Domains and DNS."""
    wire(settings)
    IdentitySnapshot.objects.create(aws_account_id="1", region=REG, identity="secret-brand.com", identity_type="DOMAIN",
                                    verified=False, dkim_status="PENDING", default_config_set="")
    IdentitySnapshot.objects.create(aws_account_id="1", region=REG, identity="ceo@secret-brand.com", identity_type="EMAIL_ADDRESS",
                                    verified=False, default_config_set="")
    login(SECURITY_ADMIN, "unscoped@example.com")
    all_text = " ".join(c.detail for c in setupcheck.run_checks(REG, sqs_client=FakeSqs(), user=None))
    assert "secret-brand.com" in all_text  # unscoped view sees everything
    c, _ = login(DELIVERABILITY_ADMIN, "scoped@example.com", scope_domains=["example.com"])
    html = c.get(reverse("setup_check")).content.decode()
    assert "secret-brand.com" not in html and "ceo@" not in html


def test_scoped_identities_helper_matches_addresses_by_domain():
    from types import SimpleNamespace as NS
    from apps.core.scope import scoped_identities
    rows = [NS(identity="example.com"), NS(identity="a@example.com"), NS(identity="Other.com"), NS(identity="b@other.com")]
    assert [r.identity for r in scoped_identities(NS(scope_domains=["EXAMPLE.com"]), rows)] == ["example.com", "a@example.com"]
    assert scoped_identities(NS(scope_domains=[]), rows) == rows and scoped_identities(None, rows) == rows


# ---------------------------------------------------------------- Compose
def compose_on(settings):
    settings.SEND_ENABLED = True
    settings.SEND_FROM_ADDRESSES = ["notifications@example.com"]
    settings.SEND_CONFIG_SET, settings.AWS_SEND_ROLE_ARN = "mc-set", "arn:aws:iam::123456789012:role/mail-console-send"


def test_compose_checks_only_exist_when_compose_is_on(settings):
    wire(settings)
    assert not [c for c in setupcheck.run_checks(REG, sqs_client=FakeSqs()) if c.group == "Compose"]
    compose_on(settings)
    assert [c for c in setupcheck.run_checks(REG, sqs_client=FakeSqs()) if c.group == "Compose"]


def test_compose_is_ready_when_an_address_is_on_the_set_is_covered_and_the_identity_is_verified(settings):
    from apps.compose.models import SenderAddress
    wire(settings)
    compose_on(settings)
    SenderAddress.objects.create(address="notifications@example.com", enabled=True)
    IdentitySnapshot.objects.update(identity="example.com")                    # the domain identity covers the address
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert (c["senders"].status, c["cset"].status) == (setupcheck.OK, setupcheck.OK) and "ident" not in c


def test_compose_problems_are_reported_with_what_to_do(settings):
    from apps.compose.models import SenderAddress
    wire(settings)
    compose_on(settings)
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["senders"].status == setupcheck.WARN and "Sending addresses" in c["senders"].fix
    settings.SEND_CONFIG_SET = "some-other-set"
    SenderAddress.objects.create(address="notifications@example.com", enabled=True)
    IdentitySnapshot.objects.update(verified=False)
    c = by_key(setupcheck.run_checks(REG, sqs_client=FakeSqs()))
    assert c["cset"].status == setupcheck.WARN and c["ident"].status == setupcheck.FAIL


def test_the_role_test_also_proves_the_send_role_without_sending(settings):
    compose_on(settings)
    settings.AWS_WRITE_ROLE_OPS_ARN = settings.AWS_WRITE_ROLE_SECURITY_ARN = ""
    called = []
    res = by_key(setupcheck.try_write_roles(REG, "ann@corp.example", "r1", assume=lambda *a: None, assume_sender=lambda *a: called.append(a)))
    assert res["send"].status == setupcheck.OK and called == [(REG, "ann@corp.example", "r1")]

    def refused(*a):
        err = Exception("AccessDenied detail that must not show")
        err.response = {"Error": {"Code": "AccessDenied"}}
        raise err
    res = by_key(setupcheck.try_write_roles(REG, "ann@corp.example", "r1", assume=lambda *a: None, assume_sender=refused))
    assert res["send"].status == setupcheck.FAIL and "AccessDenied" in res["send"].detail and "must not show" not in res["send"].detail
    settings.SEND_ENABLED = False
    assert "send" not in by_key(setupcheck.try_write_roles(REG, "ann@corp.example", "r1", assume=lambda *a: None))
