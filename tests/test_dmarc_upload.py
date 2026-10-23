import gzip
import io
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.inbound import dmarc, dmarc_upload, dmarcstats
from apps.inbound.models import DmarcReport
from apps.sesdata.models import IdentitySnapshot

from .test_views import login

pytestmark = pytest.mark.django_db
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
ALLOWED = {"example.com"}


def ts(dt):
    return int(dt.timestamp())


def xml(org="google.com", rid="r1", domain="example.com", p="none", begin=NOW - timedelta(days=1), end=NOW - timedelta(hours=1), rows=None, extra=""):
    rows = rows if rows is not None else [("203.0.113.5", 10, "pass", "pass", "none", "example.com")]
    recs = "".join(f"<record><row><source_ip>{ip}</source_ip><count>{n}</count><policy_evaluated><disposition>{disp}</disposition>"
                   f"<dkim>{dk}</dkim><spf>{sp}</spf></policy_evaluated></row><identifiers><header_from>{hf}</header_from></identifiers></record>"
                   for ip, n, dk, sp, disp, hf in rows)
    return (f"<?xml version='1.0'?>{extra}<feedback><report_metadata><org_name>{org}</org_name><report_id>{rid}</report_id>"
            f"<date_range><begin>{ts(begin)}</begin><end>{ts(end)}</end></date_range></report_metadata>"
            f"<policy_published><domain>{domain}</domain><p>{p}</p></policy_published>{recs}</feedback>").encode()


def up(data, name="report.xml"):
    return SimpleUploadedFile(name, data)


def gz(data):
    return gzip.compress(data)


def zp(*files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files:
            z.writestr(n, d)
    return b.getvalue()


def ingest(*files, allowed=ALLOWED):
    return dmarc_upload.ingest(list(files), "up@example.com", allowed=allowed, now=NOW)


# ---------------------------------------------------------------- good reports in every format
def test_xml_gzip_and_zip_are_all_accepted_and_the_numbers_are_kept():
    res = ingest(up(xml(rid="a")), up(gz(xml(rid="b")), "b.xml.gz"), up(zp(("r.xml", xml(rid="c"))), "c.zip"))
    assert [r.status for r in res] == ["added"] * 3
    r = DmarcReport.objects.get(report_id="a")
    assert (r.org_name, r.domain, r.policy, r.pass_count, r.fail_count, r.uploaded_by) == ("google.com", "example.com", "none", 10, 0, "up@example.com")
    assert r.message is None and r.uploaded_at == NOW and r.rows[0]["source_ip"] == "203.0.113.5"


def test_pass_and_fail_are_recomputed_from_validated_rows():
    ingest(up(xml(rows=[("203.0.113.5", 90, "pass", "fail", "none", "example.com"), ("198.51.100.7", 10, "fail", "fail", "reject", "example.com"),
                         ("198.51.100.8", 5, "fail", "pass", "none", "example.com")])))
    r = DmarcReport.objects.get()
    assert (r.pass_count, r.fail_count) == (95, 10)


def test_ipv6_is_normalised_and_control_characters_in_names_are_removed():
    ingest(up(xml(org="Goo\x07gle", rows=[("2001:0DB8:0000:0000:0000:0000:0000:0001", 3, "pass", "pass", "none", "example.com")]).replace(b"\x07", b" ")))
    r = DmarcReport.objects.get()
    assert r.rows[0]["source_ip"] == "2001:db8::1" and "\x07" not in r.org_name


def test_the_same_report_twice_is_a_duplicate_not_an_error_or_a_second_row():
    ingest(up(xml(rid="dup")))
    res = ingest(up(xml(rid="dup")))
    assert res[0].status == "duplicate" and DmarcReport.objects.count() == 1


def test_subdomains_of_a_watched_domain_are_accepted_but_look_alikes_are_not():
    ok = ingest(up(xml(rid="s1", domain="mail.example.com")))
    bad = ingest(up(xml(rid="s2", domain="notexample.com")), up(xml(rid="s3", domain="example.com.evil.net")), up(xml(rid="s4", domain="other.org")))
    assert ok[0].status == "added" and [r.status for r in bad] == ["error"] * 3 and "not one of the domains" in bad[0].detail


def test_with_no_watched_domains_nothing_is_accepted():
    assert ingest(up(xml()), allowed=set())[0].status == "error"


def test_watched_domains_come_from_the_synced_identities():
    IdentitySnapshot.objects.create(aws_account_id="1", region="ap-south-1", identity="Example.COM", identity_type="DOMAIN")
    IdentitySnapshot.objects.create(aws_account_id="1", region="ap-south-1", identity="ceo@brand.io", identity_type="EMAIL_ADDRESS")
    assert dmarc_upload.watched_domains() == {"example.com", "brand.io"}


# ---------------------------------------------------------------- hostile and broken input
def test_entity_expansion_dtds_and_external_entities_are_refused():
    bomb = b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY a 'aaaaaaaaaa'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;'>]><feedback>&b;</feedback>"
    xxe = b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><feedback>&e;</feedback>"
    res = ingest(up(bomb), up(xxe), up(xml(extra="<!DOCTYPE feedback [<!ENTITY e 'x'>]>")))
    assert [r.status for r in res] == ["error"] * 3 and not DmarcReport.objects.exists()


def test_a_gzip_bomb_and_a_zip_bomb_are_refused_without_exhausting_memory():
    big = b"<feedback>" + b"A" * (dmarc.MAX_XML + 10)
    res = ingest(up(gz(big), "bomb.gz"), up(zp(("b.xml", big)), "bomb.zip"))
    assert [r.status for r in res] == ["error", "error"] and not DmarcReport.objects.exists()


def test_a_zip_must_hold_exactly_one_xml_file():
    res = ingest(up(zp(("a.xml", xml(rid="z1")), ("b.xml", xml(rid="z2")))), up(zp(("readme.txt", b"hi"))))
    assert [r.status for r in res] == ["error", "error"] and not DmarcReport.objects.exists()


def test_oversized_files_are_refused_before_they_are_read():
    res = ingest(up(b"x" * (dmarc_upload.MAX_FILE_BYTES + 1)))
    assert res[0].status == "error" and "larger than" in res[0].detail


@pytest.mark.parametrize("data", [b"", b"not xml at all", b"\x1f\x8b garbage", b"PK\x03\x04 garbage", b"<html><body>hi</body></html>", b"<feedback>", b"\x00\x01\x02"])
def test_junk_is_reported_as_unreadable_not_as_a_server_error(data):
    res = ingest(up(data))
    assert res[0].status == "error" and not DmarcReport.objects.exists()


@pytest.mark.parametrize("rows,why", [
    ([("999.1.1.1", 5, "pass", "pass", "none", "example.com")], "IP address"),
    ([("not-an-ip", 5, "pass", "pass", "none", "example.com")], "IP address"),
    ([("&lt;script&gt;alert(1)&lt;/script&gt;", 5, "pass", "pass", "none", "example.com")], "IP address"),
    ([("203.0.113.5", -5, "pass", "pass", "none", "example.com")], "count"),
    ([("203.0.113.5", 10 ** 12, "pass", "pass", "none", "example.com")], "count"),
    ([("203.0.113.5", 5, "pwned", "pass", "none", "example.com")], "result value"),
    ([("203.0.113.5", 5, "pass", "pass", "drop-everything", "example.com")], "result value"),
])
def test_malformed_values_reject_the_whole_report(rows, why):
    res = ingest(up(xml(rows=rows)))
    assert res[0].status == "error" and why in res[0].detail and not DmarcReport.objects.exists()


def test_a_non_numeric_count_is_unreadable():
    data = xml().replace(b"<count>10</count>", b"<count>ten</count>")
    assert ingest(up(data))[0].status == "error"


@pytest.mark.parametrize("kw,why", [
    ({"org": ""}, "no sender organisation"), ({"rid": ""}, "no sender organisation"), ({"domain": "not a domain"}, "domain is not valid"),
    ({"begin": NOW, "end": NOW - timedelta(days=1)}, "date range"), ({"begin": NOW - timedelta(days=400), "end": NOW - timedelta(hours=1)}, "date range"),
    ({"begin": NOW + timedelta(days=5), "end": NOW + timedelta(days=6)}, "date range"),
])
def test_implausible_metadata_is_refused(kw, why):
    res = ingest(up(xml(**kw)))
    assert res[0].status == "error" and why in res[0].detail


def test_too_many_records_are_refused(monkeypatch):
    monkeypatch.setattr(dmarc_upload, "MAX_ROWS", 2)
    rows = [(f"203.0.113.{i}", 1, "pass", "pass", "none", "example.com") for i in range(3)]
    assert "more than 2 records" in ingest(up(xml(rows=rows)))[0].detail


def test_one_bad_file_does_not_stop_the_good_ones():
    res = ingest(up(b"junk"), up(xml(rid="good")), up(xml(rid="other", domain="elsewhere.org")))
    assert [r.status for r in res] == ["error", "added", "error"] and DmarcReport.objects.count() == 1


def test_the_error_text_never_leaks_internals():
    res = ingest(up(b"\x1f\x8b garbage"), up(b"<feedback><report_metadata/>"))
    assert all("Traceback" not in r.detail and "File \"" not in r.detail and "/Users/" not in r.detail for r in res)


# ---------------------------------------------------------------- the upload page
def post(client, *files):
    return client.post(reverse("dmarc_upload"), {"reports": list(files)})


@pytest.fixture
def watched():
    IdentitySnapshot.objects.create(aws_account_id="1", region="ap-south-1", identity="example.com", identity_type="DOMAIN")


def test_only_deliverability_and_security_admins_can_upload(watched):
    for role in (VIEWER, SUPPORT):
        c, _ = login(role, f"{role}@example.com")
        assert c.get(reverse("dmarc_upload")).status_code == 403 and post(c, up(xml())).status_code == 403
    assert not DmarcReport.objects.exists()
    from django.test import Client
    assert Client(HTTP_HOST="console.test").get(reverse("dmarc_upload")).status_code == 302
    for role in (DELIVERABILITY_ADMIN, SECURITY_ADMIN):
        c, _ = login(role, f"{role}@example.com")
        assert c.get(reverse("dmarc_upload")).status_code == 200


def test_uploading_through_the_page_adds_reports_shows_results_and_is_audited(watched):
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    recent = dict(begin=datetime.now(timezone.utc) - timedelta(days=1), end=datetime.now(timezone.utc) - timedelta(hours=1))
    r = post(c, up(xml(rid="p1", **recent), "ok.xml"), up(xml(rid="p1", **recent), "again.xml"), up(b"junk", "bad.txt"), up(xml(rid="p2", domain="elsewhere.org", **recent), "foreign.xml"))
    html = r.content.decode()
    assert r.status_code == 200 and "Added" in html and "Already added" in html and "Not added" in html and "ok.xml" in html
    a = AuditLog.objects.get(action="dmarc.uploaded")
    assert a.actor == "d@example.com" and a.details["files"] == 4 and a.details["added"] == 1 and a.details["duplicates"] == 1 and a.details["errors"] == 2
    assert "ok.xml" not in str(a.details) and a.details["domains"] == ["elsewhere.org", "example.com"]


def test_no_files_or_too_many_files_are_refused(watched):
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    assert c.post(reverse("dmarc_upload"), {}).status_code == 302
    many = [up(xml(rid=f"m{i}")) for i in range(dmarc_upload.MAX_FILES + 1)]
    assert post(c, *many).status_code == 302 and not DmarcReport.objects.exists()


def test_the_page_lists_the_accepted_domains_and_escapes_file_names(watched):
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    assert "example.com" in c.get(reverse("dmarc_upload")).content.decode()
    r = post(c, up(b"junk", "<img src=x onerror=alert(1)>.xml"))
    assert "<img src=x" not in r.content.decode() and "&lt;img" in r.content.decode()


def test_a_get_never_adds_anything(watched):
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    c.get(reverse("dmarc_upload") + "?reports=x")
    assert not DmarcReport.objects.exists()


# ---------------------------------------------------------------- the numbers and the verdict
def reports(domain="example.com", days=10, per_day=30, fail_per_day=0, policy="none", org="google.com"):
    now = datetime.now(timezone.utc)
    for i in range(days):
        b = now - timedelta(days=i + 1)
        rows = [("203.0.113.5", per_day - fail_per_day, "pass", "pass", "none", domain)]
        if fail_per_day:
            rows.append(("198.51.100.9", fail_per_day, "fail", "fail", "none", domain))
        dmarc_upload.ingest([up(xml(org=org, rid=f"r-{i}-{len(org)}", domain=domain, p=policy, begin=b, end=b + timedelta(hours=23), rows=rows))], "t", allowed={domain, "example.com"})


def test_overview_totals_pass_rate_policy_providers_and_days():
    reports(days=10, per_day=30, fail_per_day=3)
    (o,) = dmarcstats.overview(30)
    assert (o["domain"], o["total"], o["passed"], o["failed"], o["policy"], o["reports"]) == ("example.com", 300, 270, 30, "none", 10)
    assert o["pass_rate"] == pytest.approx(0.9) and o["providers"] == ["google.com"] and 10 <= o["days"] <= 12


def test_the_period_filters_old_reports():
    reports(days=40, per_day=5)
    assert dmarcstats.overview(7)[0]["reports"] <= 8 and dmarcstats.overview(30)[0]["reports"] > dmarcstats.overview(7)[0]["reports"]
    assert dmarcstats.overview(90)[0]["reports"] == 40


@pytest.mark.parametrize("policy,total,failed,covered,state", [
    ("quarantine", 1000, 500, 30, "enforcing"), ("reject", 5, 5, 1, "enforcing"),
    ("none", 99, 0, 30, "not_enough"), ("none", 1000, 0, 6, "not_enough"), ("none", 100, 0, 7, "ready"),
    ("none", 1000, 20, 30, "ready"), ("none", 1000, 21, 30, "not_ready"), ("", 1000, 300, 30, "not_ready"),
])
def test_readiness_thresholds(policy, total, failed, covered, state):
    assert dmarcstats.readiness(policy, total, failed, covered)[0] == state


def test_the_advice_is_cautious_and_says_what_to_do():
    assert "pct=10" in dmarcstats.readiness("none", 1000, 0, 30)[1]
    assert "Fix the failing sources" in dmarcstats.readiness("none", 1000, 500, 30)[1]


def test_sources_are_aggregated_with_the_failing_ones_first_and_a_cap(monkeypatch):
    reports(days=5, per_day=20, fail_per_day=4)
    rows, more = dmarcstats.sources("example.com", 30)
    assert [r["ip"] for r in rows] == ["198.51.100.9", "203.0.113.5"] and rows[0]["failed"] == 20 and rows[0]["passed"] == 0
    assert rows[1]["count"] == 80 and rows[1]["dkim_pass"] == 80 and more == 0
    monkeypatch.setattr(dmarcstats, "TOP_SOURCES", 1)
    assert dmarcstats.sources("example.com", 30)[1] == 1


def test_the_dmarc_page_shows_the_verdict_sources_and_who_uploaded(watched):
    reports(days=10, per_day=30, fail_per_day=0)
    c, _ = login(SUPPORT, "s@example.com")
    html = c.get(reverse("dmarc")).content.decode()
    assert "Looks ready to tighten" in html and "203.0.113.5" in html and "uploaded by" in html and "pct=10" in html
    assert "Upload reports" not in html                                     # support can read, not upload
    d, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    assert "Upload reports" in d.get(reverse("dmarc")).content.decode()


def test_bad_query_values_fall_back_safely_and_names_are_escaped(watched):
    reports(days=3, org="&lt;script&gt;alert(1)&lt;/script&gt;")
    c, _ = login(SUPPORT, "s@example.com")
    for q in ("?days=abc", "?days=999999", "?domain=nope.example", "?days=7&domain=%3Cscript%3E"):
        assert c.get(reverse("dmarc") + q).status_code == 200
    html = c.get(reverse("dmarc")).content.decode()
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html


def test_the_page_renders_with_no_reports():
    c, _ = login(SUPPORT, "s@example.com")
    assert "No DMARC reports in this period" in c.get(reverse("dmarc")).content.decode()


# ---------------------------------------------------------------- provenance: uploaded reports are unverified and cannot block real ones
def inbox_twin(org="google.com", rid="r1", domain="example.com", ok=100, bad=0):
    from apps.inbound.models import InboundMessage
    m = InboundMessage.objects.create(aws_account_id="1", region="ap-south-1", archive_message_id=f"a-{rid}", received_at=NOW, kind="dmarc_report")
    now = datetime.now(timezone.utc)
    return DmarcReport.objects.create(message=m, source="inbox", org_name=org, report_id=rid, domain=domain, begin=now - timedelta(days=1), end=now - timedelta(hours=1),
                                      policy="none", rows=[{"source_ip": "203.0.113.5", "count": ok, "disposition": "none", "dkim": "pass", "spf": "pass", "header_from": domain}],
                                      pass_count=ok, fail_count=bad)


def test_an_uploaded_report_records_the_fingerprint_of_the_original_file():
    import hashlib
    data = xml(rid="fp")
    ingest(up(data))
    r = DmarcReport.objects.get()
    assert r.source == "upload" and r.file_sha256 == hashlib.sha256(data).hexdigest()
    ingest(up(gz(xml(rid="fp2"))))
    assert DmarcReport.objects.get(report_id="fp2").file_sha256 == hashlib.sha256(gz(xml(rid="fp2"))).hexdigest()   # of what was uploaded


def live_upload(rid, n=5):
    now = datetime.now(timezone.utc)   # real clock: these tests also exercise the period filter
    return dmarc_upload.ingest([up(xml(rid=rid, begin=now - timedelta(days=1), end=now - timedelta(hours=1), rows=[("203.0.113.5", n, "pass", "pass", "none", "example.com")]))],
                               "up@example.com", allowed=ALLOWED)


def test_a_forged_upload_cannot_pre_empt_the_genuine_report_that_arrives_later():
    """The review finding: with one uniqueness key, an uploaded report could occupy the slot of the real one."""
    assert live_upload("same")[0].status == "added"
    genuine = inbox_twin(rid="same", ok=50)                         # the real one arrives by mail with the same organisation and id
    assert genuine.pk and DmarcReport.objects.filter(report_id="same").count() == 2


def test_the_same_report_present_both_ways_is_counted_once_as_the_mail_copy():
    assert live_upload("same")[0].status == "added"
    assert dmarcstats.overview(30)[0]["total"] == 5
    inbox_twin(rid="same", ok=50)
    (o,) = dmarcstats.overview(30)
    assert o["total"] == 50 and o["uploaded"] == 0 and o["reports"] == 1          # the unverified copy no longer counts
    rows, _ = dmarcstats.sources("example.com", 30)
    assert rows[0]["count"] == 50


def test_uploads_of_different_reports_still_count_and_are_flagged_as_unverified():
    reports(days=10, per_day=30)
    (o,) = dmarcstats.overview(30)
    assert o["uploaded"] == 10 and o["state"] == "ready" and "uploaded by hand" in o["advice"] and "cannot verify" in o["advice"]


def test_a_purely_inbox_domain_has_no_caveat():
    now = datetime.now(timezone.utc)
    for i in range(10):
        r = inbox_twin(rid=f"i{i}", ok=30)
        DmarcReport.objects.filter(pk=r.pk).update(begin=now - timedelta(days=i + 1), end=now - timedelta(days=i + 1) + timedelta(hours=23))
    (o,) = dmarcstats.overview(30)
    assert o["uploaded"] == 0 and o["state"] == "ready" and "uploaded by hand" not in o["advice"]


def test_the_page_labels_uploaded_reports_as_not_verified_and_the_upload_page_says_so(watched):
    reports(days=3)
    c, _ = login(DELIVERABILITY_ADMIN, "d@example.com")
    assert "uploaded, not verified" in c.get(reverse("dmarc")).content.decode()
    assert "taken at face value" in c.get(reverse("dmarc_upload")).content.decode()


def test_a_parser_failure_is_shown_as_a_plain_sentence_without_exception_names():
    d = ingest(up(b"this is not a dmarc report"))[0].detail
    assert d == "the file is not a valid DMARC aggregate report" and "ParseError" not in d
