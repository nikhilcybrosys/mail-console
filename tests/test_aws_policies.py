"""The AWS policy files are the console's security boundary, so they are tested like code.

The headline guarantee, "no console role can ever send mail", is checked here mechanically, and the policies are tied to
what the application actually calls so they can neither grant extra rights nor miss one.
"""
import fnmatch
import importlib.util
import json
import re
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.approvals.service import ACTIONS, IAM_ACTIONS
from apps.sesdata.models import AwsAccount

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "aws" / "policies"
spec = importlib.util.spec_from_file_location("aws_render", ROOT / "aws" / "render.py")
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)

SEND_ACTIONS = ["ses:SendEmail", "ses:SendBulkEmail", "ses:SendRawEmail", "ses:SendCustomVerificationEmail",
                "ses:SendTemplatedEmail", "ses:SendBulkTemplatedEmail", "ses:SendBounce"]
IDENTITY_POLICIES = ["console-read.json", "write-ops.json", "write-security.json"]
DOCUMENTED = {"__ACCOUNT_ID__", "__REGION__", "__EMAIL_DOMAIN__", "__TOPIC_ARN__", "__QUEUE_ARN__", "__APP_ROLE_ARN__", "__SERVICE_PRINCIPAL__"}
VALUES = dict(account_id="123456789012", region="ap-south-1", email_domain="corp.example",
              topic_arn="arn:aws:sns:ap-south-1:123456789012:mail-console-ses-events",
              queue_arn="arn:aws:sqs:ap-south-1:123456789012:mail-console-events", service_principal="ec2.amazonaws.com")


def load(name):
    return json.loads((POLICIES / name).read_text())


def as_list(x):
    return x if isinstance(x, list) else [x]


def statements(policy, effect):
    return [s for s in policy["Statement"] if s["Effect"] == effect]


def allowed(policy):
    out = set()
    for s in statements(policy, "Allow"):
        assert "NotAction" not in s, "NotAction in an Allow is a trap: it grants everything else"
        out.update(as_list(s["Action"]))
    return out


def pascal(snake):
    return "".join(w.capitalize() for w in snake.split("_"))


@pytest.mark.parametrize("path", sorted(POLICIES.glob("*.json")), ids=lambda p: p.name)
def test_policy_is_valid_and_uses_only_documented_placeholders(path):
    doc = json.loads(path.read_text())
    assert doc["Version"] == "2012-10-17" and doc["Statement"]
    assert set(re.findall(r"__[A-Z_]+__", path.read_text())) <= DOCUMENTED


def test_render_fills_everything_and_rejects_bad_input(tmp_path):
    args = render.argparse.Namespace(**VALUES)
    files = render.render(render.build_values(args))
    assert set(files) >= {p.name for p in POLICIES.glob("*.json")} | {"sqs-queue-attributes.json"}
    for text in files.values():
        assert not re.search(r"__[A-Z_]+__", text) and json.loads(text)
    assert json.loads(files["sqs-queue-attributes.json"])["Policy"]  # a JSON string, as the AWS CLI expects
    for bad in ({"account_id": "123"}, {"region": "mars"}, {"topic_arn": "nope"}, {"email_domain": "no-dot"}, {"service_principal": "evil.com"}):
        with pytest.raises(SystemExit):
            render.build_values(render.argparse.Namespace(**{**VALUES, **bad}))
    assert render.main(["--account-id", "123456789012", "--region", "ap-south-1", "--email-domain", "corp.example", "--topic-arn", VALUES["topic_arn"],
                        "--queue-arn", VALUES["queue_arn"], "--service-principal", "ec2.amazonaws.com", "--out", str(tmp_path / "o")]) == 0
    assert (tmp_path / "o" / "console-read.json").exists()


# ---- the headline guarantee ------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", IDENTITY_POLICIES)
def test_no_console_policy_grants_any_way_to_send_mail(name):
    for action in allowed(load(name)):
        for send in SEND_ACTIONS:
            assert not fnmatch.fnmatch(send, action), f"{name} allows {action!r}, which would permit {send}"
    assert "*" not in allowed(load(name)) and "ses:*" not in allowed(load(name))


@pytest.mark.parametrize("name", IDENTITY_POLICIES + ["permissions-boundary.json"])
def test_every_console_policy_explicitly_denies_all_seven_send_actions(name):
    denied = set()
    for s in statements(load(name), "Deny"):
        denied.update(as_list(s["Action"]))
    assert set(SEND_ACTIONS) <= denied and "ses:Send*" in denied, f"{name} must deny every ses:Send* action (an explicit Deny beats any Allow)"


def test_boundary_blocks_other_regions_and_self_escalation():
    boundary = load("permissions-boundary.json")
    sids = {s["Sid"]: s for s in boundary["Statement"]}
    assert sids["SesOnlyInTheConfiguredRegion"]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == "__REGION__"
    esc = set(as_list(sids["NoSelfEscalation"]["Action"]))
    assert {"iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary", "iam:CreateAccessKey", "iam:AttachRolePolicy"} <= esc


# ---- write roles: only as a named person, only in the configured region ------------------------------------------
@pytest.mark.parametrize("name", ["write-ops.json", "write-security.json"])
def test_write_permissions_need_a_named_person_and_the_configured_region(name):
    for s in statements(load(name), "Allow"):
        cond = s["Condition"]
        assert cond["StringLike"]["aws:SourceIdentity"] == "*@__EMAIL_DOMAIN__", s["Sid"]
        assert cond["StringEquals"]["aws:RequestedRegion"] == "__REGION__", s["Sid"]


def test_write_roles_trust_only_the_app_role_and_only_a_named_person():
    (s,) = load("trust-write-roles.json")["Statement"]
    assert s["Principal"] == {"AWS": "__APP_ROLE_ARN__"} and "sts:SetSourceIdentity" in s["Action"]
    assert s["Condition"]["StringLike"]["sts:SourceIdentity"] == "*@__EMAIL_DOMAIN__"


def test_app_role_may_assume_exactly_the_two_write_roles_with_a_named_person():
    assume = next(s for s in load("console-read.json")["Statement"] if "sts:AssumeRole" in as_list(s["Action"]))
    assert sorted(assume["Resource"]) == ["arn:aws:iam::__ACCOUNT_ID__:role/mail-console-write-ops", "arn:aws:iam::__ACCOUNT_ID__:role/mail-console-write-security"]
    assert assume["Condition"]["StringLike"]["sts:SourceIdentity"] == "*@__EMAIL_DOMAIN__"


def test_read_policy_contains_no_write_actions():
    for a in allowed(load("console-read.json")):
        svc, name = a.split(":")
        if svc == "ses":
            assert name.startswith(("Get", "List")), a
        elif svc == "sqs":
            assert name in {"ReceiveMessage", "DeleteMessage", "ChangeMessageVisibility", "GetQueueAttributes", "GetQueueUrl"}, a  # consume only: no SendMessage, no Purge
        elif svc == "cloudwatch":
            assert name == "GetMetricData", a
        else:
            assert a in {"sts:AssumeRole", "sts:SetSourceIdentity"}, a


# ---- the policies and the code agree -----------------------------------------------------------------------------
def test_read_policy_covers_exactly_the_aws_calls_the_reader_makes():
    src = (ROOT / "apps" / "sesdata" / "aws.py").read_text()
    reader = src[src.index("class SesReader"):src.index("class SesWriter")]
    calls = set(re.findall(r"self\.c\.([a-z_]+)", reader)) | set(re.findall(r'self\._call\("([a-z_]+)"', reader))
    calls -= {"exceptions"}
    needed = {"ses:" + pascal(c) for c in calls}
    granted = {a for a in allowed(load("console-read.json")) if a.startswith("ses:")}
    assert needed <= granted, f"the code calls {needed - granted} but console-read.json does not allow it"
    assert granted <= needed, f"console-read.json grants {granted - needed}, which the code never calls (least privilege)"


def test_every_approvable_action_has_its_iam_requirements_and_vice_versa():
    assert set(IAM_ACTIONS) == set(ACTIONS)


@pytest.mark.parametrize("tier,name", [("ops", "write-ops.json"), ("security", "write-security.json")])
def test_each_write_role_grants_exactly_what_its_approvable_actions_need(tier, name):
    needed = {a for action, acts in IAM_ACTIONS.items() if ACTIONS[action][1] == tier for a in acts}
    granted = {a for a in allowed(load(name)) if a.startswith("ses:")}
    assert granted == needed, f"{name}: missing {needed - granted}, extra {granted - needed}"


# ---- the pipeline plumbing -----------------------------------------------------------------------------------------
def test_queue_accepts_only_our_topic_and_topic_accepts_only_ses_in_this_account():
    (q,) = load("sqs-queue-policy.json")["Statement"]
    assert q["Principal"] == {"Service": "sns.amazonaws.com"} and q["Condition"] == {"ArnEquals": {"aws:SourceArn": "__TOPIC_ARN__"}}
    ses = next(s for s in load("sns-topic-policy.json")["Statement"] if s["Principal"] == {"Service": "ses.amazonaws.com"})
    assert ses["Action"] == "sns:Publish" and ses["Condition"]["StringEquals"] == {"AWS:SourceAccount": "__ACCOUNT_ID__"}


@pytest.mark.django_db
def test_register_aws_account_command_validates_and_is_idempotent():
    with pytest.raises(CommandError):
        call_command("register_aws_account", "main", "12345")
    call_command("register_aws_account", "main", "123456789012")
    call_command("register_aws_account", "main", "210987654321")
    assert list(AwsAccount.objects.values_list("alias", "aws_account_id")) == [("main", "210987654321")]
