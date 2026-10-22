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
