"""DMARC collection by mail adds a little to what the console may read. These tests pin exactly how little."""
import fnmatch
import json
import re

import pytest

from .test_aws_policies import IDENTITY_POLICIES, POLICIES, SEND_ACTIONS, VALUES, allowed, as_list, load, render, statements

DM = dict(VALUES, dmarc_queue_arn="arn:aws:sqs:ap-south-1:123456789012:mc-dmarc", dmarc_topic_arn="arn:aws:sns:ap-south-1:123456789012:mc-dmarc",
          dmarc_bucket="mc-dmarc-bucket", dmarc_prefix="", dmarc_rule_set="", dmarc_rule="")
RULE = "arn:aws:ses:ap-south-1:123456789012:receipt-rule-set/mail-console-dmarc:receipt-rule/dmarc-reports"


def rendered(**over):
    return render.render(render.build_values(render.argparse.Namespace(**{**DM, **over})))


def test_nothing_about_dmarc_is_rendered_unless_asked_for():
    files = render.render(render.build_values(render.argparse.Namespace(**VALUES)))
    assert not set(files) & render.DMARC_FILES and "dmarc-queue-attributes.json" not in files
    assert "dmarc" not in "".join(files.values()).lower()


def test_asking_for_it_renders_every_dmarc_file_valid_and_fully_filled():
    files = rendered()
    assert render.DMARC_FILES <= set(files) and json.loads(files["dmarc-queue-attributes.json"])["Policy"]
    for name in render.DMARC_FILES:
        assert not re.search(r"__[A-Z_]+__", files[name]) and json.loads(files[name])


@pytest.mark.parametrize("bad", [
    {"dmarc_queue_arn": ""}, {"dmarc_topic_arn": ""}, {"dmarc_bucket": ""},                   # all three or none
    {"dmarc_queue_arn": "nope"}, {"dmarc_topic_arn": "nope"}, {"dmarc_bucket": "Bad Bucket"}, {"dmarc_bucket": "x"},
    {"dmarc_prefix": "dmarc"}, {"dmarc_prefix": "../x/"}, {"dmarc_prefix": "a//b/"}, {"dmarc_prefix": "*/"},
    {"dmarc_rule_set": "has space"}, {"dmarc_rule": "*"},
])
def test_dmarc_options_are_validated_exactly(bad):
    with pytest.raises(SystemExit):
        render.build_values(render.argparse.Namespace(**{**DM, **bad}))


def test_the_app_role_extra_policy_is_one_queue_and_one_folder_read_and_cannot_send_or_write():
    pol = json.loads(rendered()["dmarc-inbound.json"])
    assert allowed(pol) == {"sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "s3:GetObject"}
    by_sid = {s["Sid"]: s for s in pol["Statement"]}
    assert by_sid["DmarcQueueConsume"]["Resource"] == DM["dmarc_queue_arn"]
    assert by_sid["ReadReportMailOnly"]["Resource"] == "arn:aws:s3:::mc-dmarc-bucket/dmarc/*"
    for a in allowed(pol):
        assert not any(fnmatch.fnmatch(send, a) for send in SEND_ACTIONS) and "*" not in a and not a.startswith(("s3:Put", "s3:Delete", "s3:List"))
    assert all("*" not in r.replace("/dmarc/*", "") for s in pol["Statement"] for r in as_list(s["Resource"]))


def test_the_boundary_with_dmarc_is_the_original_plus_exactly_one_read_only_ceiling():
    base, extra = load("permissions-boundary.json")["Statement"], load("permissions-boundary-dmarc.json")["Statement"]
    added = [s for s in extra if s not in base]
    assert [s for s in base if s not in extra] == [] and len(added) == 1
    (s,) = added
    assert (s["Effect"], s["Action"], s["Resource"]) == ("Allow", "s3:GetObject", "arn:aws:s3:::__DMARC_BUCKET__/__DMARC_PREFIX__*")
    assert {s["Sid"] for s in base if s["Effect"] == "Deny"} <= {s["Sid"] for s in extra if s["Effect"] == "Deny"}   # every original deny is still there
    # the send ban and the region and escalation denies survive in the rendered file too
    denied = {a for st in statements(json.loads(rendered()["permissions-boundary-dmarc.json"]), "Deny") for a in as_list(st["Action"])}
    assert set(SEND_ACTIONS) <= denied and "ses:Send*" in denied and "iam:CreateAccessKey" in denied


def test_only_the_named_receipt_rule_may_store_mail_or_publish_and_the_bucket_is_tls_only():
    files = rendered()
    bucket = {s["Sid"]: s for s in json.loads(files["dmarc-bucket-policy.json"])["Statement"]}
    put = bucket["OnlyTheDmarcReceiptRuleMayStoreMail"]
    assert put["Principal"] == {"Service": "ses.amazonaws.com"} and put["Action"] == "s3:PutObject" and put["Resource"] == "arn:aws:s3:::mc-dmarc-bucket/dmarc/*"
    assert put["Condition"]["StringEquals"]["AWS:SourceAccount"] == "123456789012" and put["Condition"]["ArnEquals"]["AWS:SourceArn"] == RULE
    assert bucket["TlsOnly"]["Effect"] == "Deny" and bucket["TlsOnly"]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    topic = {s["Sid"]: s for s in json.loads(files["dmarc-topic-policy.json"])["Statement"]}
    assert topic["OnlyTheDmarcReceiptRuleMayPublish"]["Condition"]["ArnEquals"]["aws:SourceArn"] == RULE
    (q,) = json.loads(files["dmarc-queue-policy.json"])["Statement"]
    assert q["Principal"] == {"Service": "sns.amazonaws.com"} and q["Condition"] == {"ArnEquals": {"aws:SourceArn": DM["dmarc_topic_arn"]}} and q["Resource"] == DM["dmarc_queue_arn"]


def test_custom_names_flow_into_the_rule_arn_and_the_prefix():
    files = rendered(dmarc_rule_set="my-set", dmarc_rule="my-rule", dmarc_prefix="reports/in/")
    assert "receipt-rule-set/my-set:receipt-rule/my-rule" in files["dmarc-bucket-policy.json"]
    assert json.loads(files["dmarc-inbound.json"])["Statement"][1]["Resource"] == "arn:aws:s3:::mc-dmarc-bucket/reports/in/*"


@pytest.mark.parametrize("name", IDENTITY_POLICIES)
def test_the_original_roles_policies_did_not_change_for_dmarc(name):
    assert rendered()[name] == render.render(render.build_values(render.argparse.Namespace(**VALUES)))[name]
    assert "s3:" not in (POLICIES / name).read_text()


def test_the_dmarc_files_are_the_only_ones_that_mention_s3():
    for path in sorted(POLICIES.glob("*.json")):
        assert ("s3:" in path.read_text()) == (path.name in render.DMARC_FILES and path.name != "dmarc-topic-policy.json" and path.name != "dmarc-queue-policy.json"), path.name
