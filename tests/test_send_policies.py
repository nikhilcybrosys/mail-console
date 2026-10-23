"""Compose adds ONE narrow exception to 'the console can never send mail'. These tests pin exactly how narrow."""
import fnmatch
import json
import re
from pathlib import Path

import pytest

from .test_aws_policies import IDENTITY_POLICIES, SEND_ACTIONS, VALUES, allowed, as_list, load, render, statements

ROOT = Path(__file__).resolve().parent.parent
SEND = dict(VALUES, send_email=["ann@corp.example"], send_from=["notifications@corp.example", "support@corp.example"], send_config_set="mail-set")
OTHER_SEND_ACTIONS = [a for a in SEND_ACTIONS if a != "ses:SendEmail"]


def rendered():
    return render.render(render.build_values(render.argparse.Namespace(**SEND)))


# ---- opt-in: nothing about sending exists unless it is asked for --------------------------------------------------
def test_without_send_options_no_send_file_is_rendered():
    files = render.render(render.build_values(render.argparse.Namespace(**VALUES)))
    assert not (set(files) & render.SEND_FILES)
    assert "mail-console-send" not in "".join(files.values())


def test_with_send_options_all_four_files_are_rendered_and_valid_json():
    files = rendered()
    assert render.SEND_FILES <= set(files)
    for name in render.SEND_FILES:
        assert not re.search(r"__[A-Z_]+__", files[name]) and json.loads(files[name])


@pytest.mark.parametrize("bad", [
    {"send_email": [], "send_from": ["a@corp.example"]}, {"send_email": ["ann@corp.example"], "send_from": []},   # one without the other
    {"send_config_set": ""}, {"send_config_set": "has space"}, {"send_config_set": "*"}, {"send_config_set": "x" * 65},       # the set is required and exact
    {"send_from": ["*@corp.example"]}, {"send_from": ["not-an-address"]}, {"send_email": ["*@corp.example"]},
    {"send_from": ["a@b.c d"]}, {"send_email": ["x" * 70 + "@corp.example"]},
])
def test_send_options_are_validated_exactly_like_the_write_roles(bad):
    with pytest.raises(SystemExit):
        render.build_values(render.argparse.Namespace(**{**SEND, **bad}))


# ---- the send role: one action, named people, listed addresses, one region ---------------------------------------
# NOTE on what IAM can and cannot do here: under SESv2, raw and templated content travel through the SAME ses:SendEmail
# permission, so IAM cannot allow "simple" and forbid "raw". The denies below close the other send actions; keeping content
# simple is the app's job (SesSender only ever builds simple content). What IAM does enforce: who (named people through the
# app role and shared secret), as which address (ses:FromAddress), on which identities and configuration set, in one region.
def test_send_role_can_do_exactly_one_thing():
    pol = load("send.json")
    assert allowed(pol) == {"ses:SendEmail"}
    (grant,) = statements(pol, "Allow")
    cond = grant["Condition"]["StringEquals"]
    assert cond["aws:SourceIdentity"] == "__SEND_EMAILS__" and cond["ses:FromAddress"] == "__SEND_FROM__" and cond["aws:RequestedRegion"] == "__REGION__"
    assert grant["Resource"] == "__SEND_RESOURCES__"   # filled by the renderer with the exact identities and the one configuration set


def test_send_resources_are_the_exact_identities_and_one_configuration_set_never_a_wildcard():
    res = json.loads(rendered()["send.json"])["Statement"][0]["Resource"]
    arn = "arn:aws:ses:ap-south-1:123456789012:"
    assert res == [arn + "identity/notifications@corp.example", arn + "identity/corp.example", arn + "identity/support@corp.example",
                   arn + "configuration-set/mail-set"]
    assert not any("*" in r for r in res)


def test_send_role_explicitly_denies_every_other_way_of_sending_and_not_the_one_it_needs():
    pol = load("send.json")
    denied = {a for s in statements(pol, "Deny") for a in as_list(s["Action"])}
    assert set(OTHER_SEND_ACTIONS) <= denied
    assert "ses:SendEmail" not in denied and not any(fnmatch.fnmatch("ses:SendEmail", d) for d in denied)   # a wildcard Deny would break the one allowed call


def test_send_boundary_caps_the_role_at_send_email_and_keeps_region_and_escalation_denies():
    b = load("permissions-boundary-send.json")
    assert allowed(b) == {"ses:SendEmail", "sts:AssumeRole", "sts:SetSourceIdentity"}
    denied = {a for s in statements(b, "Deny") for a in as_list(s["Action"])}
    assert set(OTHER_SEND_ACTIONS) <= denied and {"iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PutRolePermissionsBoundary"} <= denied
    sids = {s["Sid"]: s for s in b["Statement"]}
    assert sids["SesOnlyInTheConfiguredRegion"]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == "__REGION__"


def test_send_role_trusts_only_the_app_role_a_named_sender_and_the_shared_secret():
    from .test_aws_policies import check_trust
    check_trust("trust-send-role.json", "__SEND_EMAILS__")


def test_app_role_extra_policy_can_only_assume_the_send_role_and_has_no_ses_action():
    (s,) = load("app-assume-send.json")["Statement"]
    assert s["Resource"] == "arn:aws:iam::__ACCOUNT_ID__:role/mail-console-send"
    assert "Condition" not in s   # a SourceIdentity condition on the caller's side denies every assumption; the trust policy holds it (tested above)
    assert set(as_list(s["Action"])) == {"sts:AssumeRole", "sts:SetSourceIdentity"}


# ---- the old guarantee is untouched for everything that existed before -------------------------------------------
@pytest.mark.parametrize("name", IDENTITY_POLICIES)
def test_the_app_role_and_both_write_roles_still_cannot_send(name):
    for action in allowed(load(name)):
        assert not any(fnmatch.fnmatch(send, action) for send in SEND_ACTIONS), (name, action)
    denied = {a for s in statements(load(name), "Deny") for a in as_list(s["Action"])}
    assert set(SEND_ACTIONS) <= denied and "ses:Send*" in denied


def test_the_original_boundary_still_denies_all_sends_to_the_three_original_roles():
    denied = {a for s in statements(load("permissions-boundary.json"), "Deny") for a in as_list(s["Action"])}
    assert set(SEND_ACTIONS) <= denied and "ses:Send*" in denied


def test_only_the_send_role_policy_in_the_whole_directory_allows_any_send_action():
    for path in sorted((ROOT / "aws" / "policies").glob("*.json")):
        pol = json.loads(path.read_text())
        for s in statements(pol, "Allow"):
            for a in as_list(s["Action"]):
                grants_send = any(fnmatch.fnmatch(send, a) for send in SEND_ACTIONS)
                if path.name in {"permissions-boundary.json", "permissions-boundary-dmarc.json"} and a == "ses:*":
                    continue  # the original boundary's ceiling, overridden by its explicit Deny (tested above)
                assert not grants_send or path.name in {"send.json", "permissions-boundary-send.json"}, (path.name, a)


def test_rendered_send_policies_list_exact_addresses_and_no_wildcards():
    files = rendered()
    cond = json.loads(files["send.json"])["Statement"][0]["Condition"]["StringEquals"]
    assert cond["ses:FromAddress"] == ["notifications@corp.example", "support@corp.example"] and cond["aws:SourceIdentity"] == ["ann@corp.example"]
    for name in ("send.json", "trust-send-role.json", "app-assume-send.json"):
        assert "*@" not in files[name] and all('"*"' not in json.dumps(st.get("Condition", {})) for st in json.loads(files[name])["Statement"])
