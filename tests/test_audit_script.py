"""The read-only AWS audit script: it must never call a mutating API and never write its report into the repository."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("phase0_audit", ROOT / "scripts" / "phase0_audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class Client:
    def __init__(self):
        self.called = []

    def __getattr__(self, name):
        def call(*a, **k):
            self.called.append(name)
            return {}
        return call


@pytest.mark.parametrize("name", ["get_account", "list_email_identities", "describe_instances", "batch_get_metric_data", "get_paginator"])
def test_read_only_calls_pass_through(name):
    c = Client()
    getattr(audit.ReadOnly(c), name)()
    assert c.called == [name]


@pytest.mark.parametrize("name", [
    "send_email", "send_raw_email", "delete_suppressed_destination", "put_suppressed_destination", "put_account_sending_attributes",
    "create_email_identity", "delete_email_identity", "update_configuration_set_event_destination", "assume_role", "create_import_job",
    "put_email_identity_dkim_attributes", "attach_user_policy", "create_access_key"])
def test_mutating_calls_are_refused_before_reaching_aws(name):
    c = Client()
    with pytest.raises(PermissionError):
        getattr(audit.ReadOnly(c), name)
    assert c.called == []


def test_report_cannot_be_written_inside_the_repository(tmp_path):
    for bad in (ROOT / "report.json", ROOT / "docs" / "x.json", ROOT):
        with pytest.raises(SystemExit):
            audit.resolve_out(bad)
    assert audit.resolve_out(tmp_path / "ok.json") == (tmp_path / "ok.json").resolve()
    assert str(audit.resolve_out("~/ses-audit-report.json")).startswith(str(Path.home()))


def test_script_never_names_a_mutating_api():
    src = (ROOT / "scripts" / "phase0_audit.py").read_text()
    import re
    called = set(re.findall(r"\.((?:put|create|delete|update|send|attach|detach|assume|set|start|stop|terminate|run)_[a-z_]+)\(", src))
    assert not called, f"audit script calls mutating APIs: {called}"


# ---- what the audit reports (against fake AWS clients, never the real one) ----------------------------------------
import datetime as _dt
import json as _json


class FakeSes:
    def get_account(self):
        return {"ProductionAccessEnabled": True, "SendingEnabled": True, "EnforcementStatus": "HEALTHY", "SendQuota": {"Max24HourSend": 50000.0}}

    def list_email_identities(self, **kw):  # the summary has no VerifiedForSendingStatus: the detail call does
        return {"EmailIdentities": [{"IdentityName": "example.com", "IdentityType": "DOMAIN"}]}

    def get_email_identity(self, **kw):
        return {"VerifiedForSendingStatus": True, "DkimAttributes": {"Status": "SUCCESS", "SigningAttributesOrigin": "AWS_SES"},
                "MailFromAttributes": {"MailFromDomain": "bounce.example.com"}, "ConfigurationSetName": "default-set"}

    def list_configuration_sets(self, **kw):
        return {"ConfigurationSets": ["default-set"]}

    def get_configuration_set_event_destinations(self, **kw):
        return {"EventDestinations": []}

    def list_suppressed_destinations(self, **kw):
        return {"SuppressedDestinationSummaries": [{}, {}]}


class FakeCloudWatch:
    def get_metric_data(self, **kw):
        return {"MetricDataResults": [{"Values": [3.0, 4.0]}]}


def test_identity_verification_comes_from_the_detail_call():
    out = audit.audit_region("ap-south-1", ses=FakeSes(), cw=FakeCloudWatch())
    ident = out["identities"][0]
    assert ident["verified"] is True and ident["default_config_set"] == "default-set" and ident["mail_from"] == "bounce.example.com"
    assert out["suppression_count"] == 2 and out["sends_last_14d_daily"] == [3, 4]
    assert out["config_sets"] == [{"name": "default-set", "destinations": []}]  # a set with no destination publishes nothing


class FakeIam:
    KEY = "AKIAFAKEFAKEFAKE1234"

    def __init__(self):
        self.pages = {None: {"Users": [{"UserName": "alice", "CreateDate": _dt.datetime(2026, 1, 1)}, {"UserName": "James", "CreateDate": _dt.datetime(2026, 1, 1)}],
                             "IsTruncated": True, "Marker": "m2"},
                      "m2": {"Users": [{"UserName": "mail-smtp-user", "CreateDate": _dt.datetime(2026, 2, 2)}, {"UserName": "bob", "CreateDate": _dt.datetime(2026, 3, 3)}],
                             "IsTruncated": False}}

    GROUPS = {"carol": ["mailers"], "dave": ["staff"]}

    def list_users(self, Marker=None):
        if Marker == "m2":  # carol and dave have unremarkable names; only their group tells the story
            return {"Users": self.pages["m2"]["Users"] + [{"UserName": "carol", "CreateDate": _dt.datetime(2026, 4, 4)}, {"UserName": "dave", "CreateDate": _dt.datetime(2026, 4, 4)}],
                    "IsTruncated": False}
        return self.pages[Marker]

    def list_groups_for_user(self, UserName):
        return {"Groups": [{"GroupName": g} for g in self.GROUPS.get(UserName, [])]}

    def list_attached_group_policies(self, GroupName):
        return {"AttachedPolicies": []}

    def list_group_policies(self, GroupName):
        return {"PolicyNames": ["send"] if GroupName == "mailers" else []}

    def get_group_policy(self, GroupName, PolicyName):
        return {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "ses:SendRawEmail", "Resource": "*"}]}}

    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": []}

    def list_user_policies(self, UserName):
        return {"PolicyNames": ["send-mail"] if UserName == "bob" else []}

    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "ses:SendRawEmail", "Resource": "*"}]}}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [{"AccessKeyId": self.KEY, "Status": "Active", "CreateDate": _dt.datetime(2026, 2, 2)}]}

    def get_access_key_last_used(self, AccessKeyId):
        if AccessKeyId != self.KEY:
            raise AssertionError("wrong key looked up")
        return {"AccessKeyLastUsed": {"ServiceName": "N/A"}}  # AWS says N/A (and no date) for a key that was never used


def test_iam_audit_flags_real_ses_users_and_not_names_that_merely_contain_ses():
    found = {u["user"]: u for u in audit.audit_iam(FakeIam())}
    assert set(found) == {"mail-smtp-user", "bob", "carol"}, "James must not match 'ses'; second-page users must be found; dave (group without SES) must not be flagged"
    assert any("SES permissions" in w for w in found["bob"]["why"])  # found by reading the inline policy, not by its name
    assert found["mail-smtp-user"]["keys"][0]["last_used"] is None and found["mail-smtp-user"]["keys"][0]["status"] == "Active"


def test_report_never_contains_a_full_access_key_id():
    text = _json.dumps(audit.audit_iam(FakeIam()), default=str)
    assert FakeIam.KEY not in text and "...1234" not in text and '"id_suffix": "1234"' in text


def test_permissions_inherited_through_a_group_are_reported():
    """A user with an ordinary name and no policies of its own can still send mail through a group (as real SMTP users do)."""
    found = {u["user"]: u for u in audit.audit_iam(FakeIam())}
    assert any("member of group 'mailers'" in w and "SES permissions" in w for w in found["carol"]["why"])
    assert "dave" not in found
