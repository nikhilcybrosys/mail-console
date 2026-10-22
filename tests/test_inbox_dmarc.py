import gzip
import io
import time
import zipfile
from datetime import datetime, timezone

import pytest
from django.test import Client
from django.urls import reverse

from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.inbound import dmarc
from apps.inbound.models import DmarcReport, InboundAttachment, InboundMessage

pytestmark = pytest.mark.django_db

XML = b"""<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><report_id>r-1</report_id>
<date_range><begin>1760918400</begin><end>1761004800</end></date_range></report_metadata>
<policy_published><domain>Example.com</domain><p>none</p></policy_published>
<record><row><source_ip>1.2.3.4</source_ip><count>10</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record>
<record><row><source_ip>9.9.9.9</source_ip><count>4</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record></feedback>"""


def test_parse_plain_gzip_and_zip():
    for raw in (XML, gzip.compress(XML)):
        r = dmarc.parse(dmarc.unpack(raw))
        assert r["domain"] == "example.com" and r["pass_count"] == 10 and r["fail_count"] == 4 and r["policy"] == "none"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.xml", XML)
    assert dmarc.parse(dmarc.unpack(buf.getvalue()))["org_name"] == "google.com"


def test_decompression_bomb_and_xml_attacks_are_rejected():
    bomb = gzip.compress(b"<feedback>" + b"A" * (dmarc.MAX_XML + 10) + b"</feedback>")
    with pytest.raises(dmarc.DmarcError):
        dmarc.unpack(bomb)
    xxe = b'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback>&x;</feedback>'
    with pytest.raises(dmarc.DmarcError):
        dmarc.parse(xxe)
    billion = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><feedback>&b;</feedback>'
    with pytest.raises(dmarc.DmarcError):
        dmarc.parse(billion)
    with pytest.raises(dmarc.DmarcError):
        dmarc.parse(b"<html/>")


def login(role, **kw):
    u = User.objects.create_user(f"{role}@example.com", role=role, **kw)
    c = Client(HTTP_HOST="console.test")
    c.force_login(u)
    s = c.session
    s["session_started"] = s["last_seen"] = s["login_at"] = s["step_up_at"] = time.time()
    s.save()
    return c


def mkmsg():
    return InboundMessage.objects.create(aws_account_id="1", region="ap-south-1", archive_message_id="a1", received_at=datetime.now(timezone.utc),
                                         from_addr="bob@x.com", subject="Re: invoice", verdicts={"spf": "PASS", "dmarc": "FAIL"})


def test_viewer_cannot_see_inbox_support_can():
    mkmsg()
    assert login("viewer").get(reverse("inbox")).status_code == 403
    assert login("support").get(reverse("inbox")).status_code == 200


def test_pages_render():
    m = mkmsg()
    DmarcReport.objects.create(message=m, org_name="g", report_id="1", domain="example.com", begin=m.received_at, end=m.received_at, policy="none",
                               rows=[{"source_ip": "9.9.9.9", "count": 4, "dkim": "fail", "spf": "fail", "disposition": "none", "header_from": "example.com"}], pass_count=1, fail_count=4)
    c = login("support")
    for name, args in (("inbox", []), ("dmarc", []), ("inbound_detail", [m.pk])):
        assert c.get(reverse(name, args=args)).status_code == 200


def test_inbound_body_needs_reason_and_is_audited():
    m = mkmsg()
    c = login("support")
    assert c.post(reverse("inbound_body", args=[m.pk]), {"reason": ""}).status_code == 400
    assert c.post(reverse("inbound_body", args=[m.pk]), {"reason": "ticket 9"}).status_code == 200
    assert AuditLog.objects.filter(action="inbound.body.view").exists()


@pytest.mark.parametrize("state", ["pending", "infected", "failed"])
def test_unclean_attachments_are_never_downloadable(state):
    m = mkmsg()
    InboundAttachment.objects.create(message=m, index=0, filename="x.pdf", content_type="application/pdf", size=1, s3_key="k", scan_state=state)
    assert login("support").get(reverse("inbound_attachment", args=[m.pk, 0])).status_code == 404


def test_clean_attachment_redirects_to_short_presigned_url_and_audits(monkeypatch, settings):
    settings.CONTENT_BUCKET = "bucket"
    m = mkmsg()
    InboundAttachment.objects.create(message=m, index=0, filename='ev"il\r\n.pdf', content_type="application/pdf", size=1, s3_key="k", scan_state="clean")
    seen = {}

    class S3:
        def generate_presigned_url(self, op, ExpiresIn, Params):
            seen.update(Params, expires=ExpiresIn)
            return "https://s3.example/signed"
    monkeypatch.setattr("apps.inbound.pages.boto3.client", lambda *_: S3())
    r = login("support").get(reverse("inbound_attachment", args=[m.pk, 0]))
    assert r.status_code == 302 and r["Location"] == "https://s3.example/signed" and seen["expires"] == 60
    assert "\r" not in seen["ResponseContentDisposition"] and "\n" not in seen["ResponseContentDisposition"] and seen["ResponseContentType"] == "application/octet-stream"
    assert AuditLog.objects.filter(action="inbound.attachment.download").exists()
