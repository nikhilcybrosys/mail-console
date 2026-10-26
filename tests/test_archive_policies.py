"""Reading the mail archive adds a little to what the console may read. These tests pin exactly how little."""
import fnmatch
import json
import re

import pytest

from .test_aws_policies import IDENTITY_POLICIES, POLICIES, SEND_ACTIONS, VALUES, allowed, as_list, load, render, statements
from .test_dmarc_policies import DM

ARCHIVE = "arn:aws:ses:ap-south-1:123456789012:mailmanager-archive/a-abc123"
KEY = "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-3333-4444-555555555555"
AR = dict(VALUES, archive_arn=ARCHIVE, archive_kms_key_arn=KEY)


def rendered(base=AR, **over):
    return render.render(render.build_values(render.argparse.Namespace(**{**base, **over})))


def test_nothing_about_the_archive_is_rendered_unless_asked_for():
    files = render.render(render.build_values(render.argparse.Namespace(**VALUES)))
    assert not set(files) & render.ARCHIVE_FILES and render.EXTENDED_BOUNDARY not in files
    assert "mailmanager" not in "".join(files.values()) and "kms:" not in "".join(files.values())


def test_asking_for_it_renders_a_valid_policy_and_an_extended_boundary():
    files = rendered()
    assert render.ARCHIVE_FILES <= set(files) and render.EXTENDED_BOUNDARY in files
    for name in (*render.ARCHIVE_FILES, render.EXTENDED_BOUNDARY):
        assert not re.search(r"__[A-Z_]+__", files[name]) and json.loads(files[name])


@pytest.mark.parametrize("bad", [
    {"archive_arn": ""}, {"archive_kms_key_arn": ""},                                           # both or neither
    {"archive_arn": "nope"}, {"archive_arn": "arn:aws:ses:ap-south-1:123456789012:identity/x"}, {"archive_arn": ARCHIVE + "/../x"},
    {"archive_kms_key_arn": "nope"}, {"archive_kms_key_arn": "arn:aws:kms:ap-south-1:123456789012:alias/x"},
    {"archive_arn": ARCHIVE.replace("ap-south-1", "us-east-1")},                                # another region than --region
    {"archive_kms_key_arn": KEY.replace("ap-south-1", "us-east-1")},
])
def test_archive_options_are_validated_exactly(bad):
    with pytest.raises(SystemExit):
        render.build_values(render.argparse.Namespace(**{**AR, **bad}))


def test_the_app_role_extra_policy_only_reads_one_archive_and_decrypts_with_one_key():
    pol = json.loads(rendered()["archive-read.json"])
    assert allowed(pol) == {"ses:GetArchive", "ses:StartArchiveSearch", "ses:GetArchiveSearch", "ses:GetArchiveSearchResults",
                            "ses:GetArchiveMessageContent", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"}
    by_sid = {s["Sid"]: s for s in pol["Statement"]}
    assert by_sid["ReadTheMailArchive"]["Resource"] == ARCHIVE and by_sid["DecryptTheMailArchive"]["Resource"] == KEY
    cond = by_sid["DecryptTheMailArchive"]["Condition"]["StringEquals"]
    assert cond == {"kms:ViaService": "ses.ap-south-1.amazonaws.com", "kms:CallerAccount": "123456789012"}    # only through SES, only from this account
    for a in allowed(pol):
        assert not any(fnmatch.fnmatch(send, a) for send in SEND_ACTIONS) and "*" not in a
        assert not a.startswith(("ses:Create", "ses:Delete", "ses:Put", "ses:Update", "ses:Send", "kms:Encrypt", "kms:ReEncrypt", "kms:CreateGrant", "kms:Schedule"))
    assert all("*" not in r for s in pol["Statement"] for r in as_list(s["Resource"]))


def test_the_extended_boundary_is_the_original_plus_exactly_one_key_ceiling():
    files = rendered()
    base, extra = json.loads(files["permissions-boundary.json"])["Statement"], json.loads(files[render.EXTENDED_BOUNDARY])["Statement"]
    added = [s for s in extra if s not in base]
    assert [s for s in base if s not in extra] == [] and len(added) == 1
    (s,) = added
    assert (s["Effect"], s["Resource"]) == ("Allow", KEY) and set(as_list(s["Action"])) == {"kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"}
    assert s["Condition"]["StringEquals"]["kms:ViaService"] == "ses.ap-south-1.amazonaws.com"
    denied = {a for st in statements(json.loads(files[render.EXTENDED_BOUNDARY]), "Deny") for a in as_list(st["Action"])}
    assert set(SEND_ACTIONS) <= denied and "ses:Send*" in denied and "iam:CreateAccessKey" in denied


def test_dmarc_and_the_archive_together_give_one_boundary_with_both_additions():
    files = rendered(DM, archive_arn=ARCHIVE, archive_kms_key_arn=KEY)
    sids = [s["Sid"] for s in json.loads(files[render.EXTENDED_BOUNDARY])["Statement"]]
    assert "DmarcReportMailReadCeiling" in sids and "MailArchiveKeyCeiling" in sids and len(sids) == len(set(sids))
    assert sids.count("NoConsoleRoleCanEverSendMail") == 1


@pytest.mark.parametrize("name", IDENTITY_POLICIES)
def test_the_original_roles_policies_do_not_change_for_the_archive(name):
    assert rendered()[name] == render.render(render.build_values(render.argparse.Namespace(**VALUES)))[name]


def test_only_the_archive_and_dmarc_files_in_the_whole_directory_mention_kms_or_the_archive():
    for path in sorted(POLICIES.glob("*.json")):
        text = path.read_text()
        assert ("kms:" in text or "mailmanager" in text or "Archive" in text) == (path.name in render.ARCHIVE_FILES), path.name


def test_the_fragments_use_only_documented_placeholders():
    from .test_aws_policies import DOCUMENTED
    for path in (POLICIES / "fragments").glob("*.json"):
        assert set(re.findall(r"__[A-Z_]+__", path.read_text())) <= DOCUMENTED and json.loads(path.read_text()), path.name
