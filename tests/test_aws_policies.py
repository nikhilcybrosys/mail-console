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
DOCUMENTED = {"__EXTERNAL_ID__", "__ACCOUNT_ID__", "__REGION__", "__EMAIL_DOMAIN__", "__TOPIC_ARN__", "__QUEUE_ARN__", "__APP_ROLE_ARN__", "__SERVICE_PRINCIPAL__"}
VALUES = dict(account_id="123456789012", region="ap-south-1", email_domain="corp.example",
              topic_arn="arn:aws:sns:ap-south-1:123456789012:mail-console-ses-events",
              queue_arn="arn:aws:sqs:ap-south-1:123456789012:mail-console-events", service_principal="ec2.amazonaws.com", external_id="x" * 32)


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
                        "--queue-arn", VALUES["queue_arn"], "--service-principal", "ec2.amazonaws.com", "--external-id", "y" * 32, "--out", str(tmp_path / "o")]) == 0
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


def test_write_roles_trust_only_the_app_role_a_named_person_and_the_shared_secret():
    (s,) = load("trust-write-roles.json")["Statement"]
    assert s["Principal"] == {"AWS": "__APP_ROLE_ARN__"} and "sts:SetSourceIdentity" in s["Action"]
    assert s["Condition"]["StringLike"]["sts:SourceIdentity"] == "*@__EMAIL_DOMAIN__"
    assert s["Condition"]["StringEquals"] == {"sts:ExternalId": "__EXTERNAL_ID__"}  # co-hosted programs without the secret are refused


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


def test_a_secret_is_generated_when_none_is_given_and_bad_ones_are_rejected(capsys):
    args = lambda **kw: render.argparse.Namespace(**{**VALUES, "external_id": "", **kw})
    a, b = render.build_values(args())["__EXTERNAL_ID__"], render.build_values(args())["__EXTERNAL_ID__"]
    assert a != b and len(a) >= 32  # random each time
    for bad in ("short", "has spaces in it and is long enough", "x" * 300, "semi;colon" + "x" * 20):
        with pytest.raises(SystemExit):
            render.build_values(args(external_id=bad))


def test_assuming_a_write_role_presents_the_secret(settings, monkeypatch):
    from apps.sesdata import aws
    seen = {}

    class Sts:
        def assume_role(self, **kw):
            seen.update(kw)
            return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}
    monkeypatch.setattr(aws.boto3, "client", lambda svc, **kw: Sts() if svc == "sts" else object())
    settings.AWS_WRITE_ROLE_OPS_ARN, settings.AWS_WRITE_ROLE_EXTERNAL_ID = "arn:aws:iam::123456789012:role/mail-console-write-ops", "s3cr3t" * 5
    aws.assume_writer("ap-south-1", "ops", "ann@corp.example", "7")
    assert seen["ExternalId"] == "s3cr3t" * 5 and seen["SourceIdentity"] == "ann@corp.example" and seen["DurationSeconds"] == 900


def _import_settings(**env):
    import os, subprocess, sys
    base = {"PATH": os.environ["PATH"], "MC_SECRET_KEY": "x" * 40, "MC_DEBUG": "0", "MC_CONSOLE_HOST": "c.example"}
    p = subprocess.run([sys.executable, "-c", "import config.settings"], cwd=ROOT, env={**base, **env}, capture_output=True, text=True)
    return p.returncode, p.stderr


def test_production_refuses_write_roles_without_the_shared_secret():
    role = {"MC_AWS_WRITE_ROLE_OPS_ARN": "arn:aws:iam::123456789012:role/mail-console-write-ops"}
    code, err = _import_settings(**role)
    assert code != 0 and "MC_AWS_WRITE_ROLE_EXTERNAL_ID" in err
    assert _import_settings(**role, MC_AWS_WRITE_ROLE_EXTERNAL_ID="z" * 32)[0] == 0
    assert _import_settings()[0] == 0  # no write roles configured: nothing to protect, no complaint
