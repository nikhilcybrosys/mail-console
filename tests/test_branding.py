"""Settings > Appearance: who may change the look, what is checked before anything is saved, and how it is served."""
import os
import struct
import time
import zlib

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.core import branding
from apps.core.models import BrandImage, Branding
from apps.core.rbac import CAPABILITIES, DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER

from .test_views import login

pytestmark = pytest.mark.django_db
URL = "/settings/appearance/"


def png(w=2, h=2, noise=False):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    rows = b"".join(b"\x00" + (os.urandom(3 * w) if noise else b"\xcc\x44\x30" * w) for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def ico():
    image = png(16, 16)
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(image), 22) + image


SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><title>Mark</title><defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient></defs><rect width="10" height="10" fill="url(#g)" style="stroke:#000;stroke-width:1"/><path d="M1 1L9 9"/></svg>'


def up(name, data, kind="image/png"):
    return SimpleUploadedFile(name, data, content_type=kind)


def admin():
    return login(SECURITY_ADMIN, "boss@example.com", step_up=True)[0]


def save(c, **fields):
    return c.post(URL, {"name": "", "login_text": "", "footer_text": "", "accent": "", "default_theme": "system", "default_density": "compact", **fields})


def anon():
    return Client(HTTP_HOST="console.test")


# ------------------------------------------------------------------ who may
def test_only_security_admin_has_the_capability():
    assert CAPABILITIES["manage_branding"] == {SECURITY_ADMIN}


@pytest.mark.parametrize("role", [VIEWER, SUPPORT, DELIVERABILITY_ADMIN])
def test_other_roles_are_refused_and_cannot_save(role):
    c = login(role, f"{role}@example.com", step_up=True)[0]
    assert c.get(URL).status_code == 403
    assert save(c, name="Hacked").status_code == 403
    assert c.post(reverse("appearance_reset")).status_code == 403
    assert c.post(reverse("appearance_preview"), {}).status_code == 403
    assert not Branding.objects.exists()
    assert "Appearance" not in c.get(reverse("dashboard")).content.decode()


def test_anonymous_is_sent_to_sign_in():
    for path in (URL, reverse("appearance_reset"), reverse("appearance_preview")):
        r = anon().get(path) if path == URL else anon().post(path)
        assert r.status_code == 302 and r["Location"].startswith("/login/")


def test_saving_needs_a_fresh_passkey():
    c = login(SECURITY_ADMIN, "boss@example.com")[0]
    r = c.get(URL)
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up"))
    r = save(c, name="Acme")
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up")) and not Branding.objects.exists()
    r = c.post(reverse("appearance_reset"))
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up"))


def test_the_page_and_the_menu_item_show_for_the_admin():
    c = admin()
    html = c.get(URL).content.decode()
    assert "Save appearance" in html and "Reset to default" in html
    assert 'href="/settings/appearance/"' in c.get(reverse("dashboard")).content.decode()


# ------------------------------------------------------------------ saving text, colour, defaults
def test_saved_look_reaches_every_page_and_is_audited():
    c = admin()
    r = save(c, name="Acme Mail", accent="#1f4fbf", login_text="Welcome to Acme", footer_text="Acme Inc. internal tool",
             default_theme="dark", default_density="comfortable")
    assert r.status_code == 302
    row = Branding.objects.get()
    assert (row.name, row.accent, row.default_theme, row.default_density, row.updated_by) == ("Acme Mail", "#1F4FBF", "dark", "comfortable", "boss@example.com")
    page = c.get(reverse("dashboard")).content.decode()
    assert "Acme Mail" in page and "Acme Inc. internal tool" in page and 'data-default-theme="dark"' in page and 'data-default-density="comfortable"' in page
    assert '<link rel="icon"' in page
    login_page = anon().get("/login/").content.decode()  # signed out: the sign-in page carries the look too
    assert "Acme Mail" in login_page and "Welcome to Acme" in login_page and "Acme Inc. internal tool" in login_page
    css = anon().get("/theme.css").content.decode()
    assert "--accent:#1F4FBF" in css and "--accent-soft:" in css and '[data-theme="dark"]' in css
    entry = AuditLog.objects.get(action="branding.updated")
    assert entry.actor == "boss@example.com" and entry.details["changed"]["name"] == ["", "Acme Mail"]


def test_blank_fields_fall_back_to_the_environment(settings):
    settings.BRAND_NAME = "From Env"
    save(admin(), name="")
    assert "From Env" in anon().get("/login/").content.decode()


@pytest.mark.parametrize("field,value", [
    ("name", "x" * 41), ("name", "two\nlines"), ("login_text", "y" * 161), ("footer_text", "z" * 201), ("footer_text", "a b"),
    ("accent", "red"), ("accent", "#12"), ("accent", "#1F4FBF;} body{display:none"), ("accent", "#FFFF00"), ("accent", "#FFFFFF"), ("accent", "#888888"),
    ("default_theme", "neon"), ("default_density", "huge"),
])
def test_bad_text_is_refused_and_nothing_is_saved(field, value):
    c = admin()
    r = save(c, **{field: value})
    assert r.status_code == 200 and "Nothing was saved" in r.content.decode()
    assert not Branding.objects.exists() and not AuditLog.objects.filter(action="branding.updated").exists()


def test_text_is_escaped_where_it_is_shown():
    save(admin(), name="<script>alert(1)</script>", footer_text='"><img src=x onerror=alert(1)>')
    page = anon().get("/login/").content.decode()
    assert "<script>alert(1)</script>" not in page and "<img src=x" not in page and "&lt;script&gt;" in page


@pytest.mark.parametrize("accent", ["#1F4FBF", "#CF4430", "#767676", "#595959", "#7A3E00", "#C8341F", "#2A62C9"])
def test_every_derived_colour_keeps_text_readable(accent):
    if not branding.usable_accent(accent):
        pytest.skip("too light to be accepted")
    from .test_ui_contract import ratio
    t = branding.accent_tones(accent)
    assert ratio("#FFFFFF", t["accent"]) >= 4.5 and ratio("#FFFFFF", t["hover"]) >= 4.5
    assert ratio(t["light_text"], t["light_soft"]) >= 4.5 and ratio(t["light_text"], "#FFFFFF") >= 4.5
    assert ratio(t["dark_text"], t["dark_soft"]) >= 4.5 and ratio(t["dark_text"], "#151517") >= 4.5


# ------------------------------------------------------------------ images: accepted
def test_a_png_logo_is_stored_served_and_audited_without_its_bytes():
    c = admin()
    data = png()
    r = save(c, logo=up("logo.png", data))
    assert r.status_code == 302
    img = BrandImage.objects.get(kind="logo")
    assert bytes(img.data) == data and img.content_type == "image/png" and img.sha256 == branding.digest(data)
    page = c.get(reverse("dashboard")).content.decode()
    assert f"/brand/logo?v={img.sha256[:12]}" in page
    served = anon().get("/brand/logo")   # public: the sign-in page needs it
    assert served.status_code == 200 and served["Content-Type"] == "image/png" and served.content == data
    assert served["X-Content-Type-Options"] == "nosniff" and "sandbox" in served["Content-Security-Policy"]
    assert "public" in served["Cache-Control"]
    again = anon().get("/brand/logo", HTTP_IF_NONE_MATCH=served["ETag"])
    assert again.status_code == 304 and again.content == b""
    entry = AuditLog.objects.get(action="branding.updated")
    assert entry.details["images"] == {"logo": img.sha256[:12]} and str(data) not in str(entry.details)


def test_one_logo_serves_both_themes_until_a_dark_one_is_uploaded():
    c = admin()
    save(c, logo=up("l.png", png()))
    page = anon().get("/login/").content.decode()
    assert page.count("/brand/logo?v=") >= 2 and "mark-white" not in page.split("auth-brand")[0]
    save(c, logo_dark=up("d.png", png(3, 3)))
    assert "/brand/logo-dark?v=" in anon().get("/login/").content.decode()


def test_svg_and_ico_favicons_are_accepted_and_ico_is_not_a_logo():
    c = admin()
    assert save(c, favicon=up("f.ico", ico(), "image/x-icon")).status_code == 302
    assert BrandImage.objects.get(kind="favicon").content_type == "image/x-icon"
    assert save(c, favicon=up("f.svg", SVG.encode(), "image/svg+xml")).status_code == 302
    assert anon().get("/brand/favicon")["Content-Type"] == "image/svg+xml"
    r = save(c, logo=up("l.ico", ico(), "image/x-icon"))
    assert r.status_code == 200 and "only be used as the favicon" in r.content.decode() and not BrandImage.objects.filter(kind="logo").exists()


def test_a_plain_svg_logo_is_accepted():
    assert branding.inspect_image(SVG.encode(), "logo") == "image/svg+xml"
    assert branding.inspect_image(b"\xef\xbb\xbf<?xml version='1.0' encoding='UTF-8'?>" + SVG.encode(), "logo") == "image/svg+xml"
    assert branding.inspect_image(b"<!-- made by a tool -->" + SVG.encode(), "logo") == "image/svg+xml"


# ------------------------------------------------------------------ images: refused
def _svg(inner="", attrs="", root_extra=""):
    return f'<svg xmlns="http://www.w3.org/2000/svg" {root_extra}{attrs}>{inner}</svg>'.encode()


BAD = {
    "empty": b"",
    "html renamed": b"<html><script>alert(1)</script></html>",
    "text": b"hello",
    "too big": png(500, 500, noise=True),
    "png too wide": png(1025, 1),
    "png damaged crc": png()[:30] + b"\x00\x00" + png()[32:],
    "png truncated": png()[:-8],
    "png header only": b"\x89PNG\r\n\x1a\n",
    "svg script": _svg("<script>alert(1)</script>"),
    "svg foreignObject": _svg("<foreignObject><div/></foreignObject>"),
    "svg onload": _svg(attrs='onload="alert(1)"'),
    "svg onclick on shape": _svg('<rect width="1" height="1" onclick="alert(1)"/>'),
    "svg href link": _svg('<a href="https://evil.example"><rect width="1" height="1"/></a>'),
    "svg image": _svg('<image href="https://evil.example/x.png"/>'),
    "svg use": _svg('<use href="#a"/>'),
    "svg xlink": b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><rect width="1" height="1" xlink:href="#a"/></svg>',
    "svg doctype": b'<!DOCTYPE svg [<!ENTITY a "bbbb">]><svg xmlns="http://www.w3.org/2000/svg"/>',
    "svg entity bomb": b'<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;">]><svg xmlns="http://www.w3.org/2000/svg">&b;</svg>',
    "svg stylesheet pi": b'<?xml-stylesheet href="https://evil.example/a.css"?><svg xmlns="http://www.w3.org/2000/svg"/>',
    "svg style element": _svg("<style>rect{fill:url(https://evil.example)}</style>"),
    "svg style url": _svg('<rect width="1" height="1" style="fill:url(https://evil.example/a)"/>'),
    "svg style import": _svg('<rect width="1" height="1" style="@import url(x)"/>'),
    "svg style escape": _svg('<rect width="1" height="1" style="fill:\\75rl(x)"/>'),
    "svg fill external": _svg('<rect width="1" height="1" fill="url(https://evil.example/a#b)"/>'),
    "svg text node": _svg("<g>visible text</g>"),
    "svg text element": _svg("<text>hi</text>"),
    "svg nested svg": _svg('<svg><rect width="1" height="1"/></svg>'),
    "svg other namespace root": b'<svg xmlns="http://example.com/ns"><rect/></svg>',
    "svg foreign namespace element": b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:x="http://example.com/x"><x:y/></svg>',
    "svg animate": _svg('<rect width="1" height="1"><animate attributeName="fill" to="red"/></rect>'),
    "svg plain doctype": b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>',
    "svg without namespace": b"<svg><rect width='1' height='1'/></svg>",
    "svg foreign rect": b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:x="http://example.com/x"><x:rect/></svg>',
    "svg style url no slash": _svg('<rect width="1" height="1" style="fill:url(x)"/>'),
    "svg style expression": _svg('<rect width="1" height="1" style="width:expression(x)"/>'),
    "svg too deep": _svg("<g>" * 25 + "</g>" * 25),
    "svg too many elements": _svg('<rect width="1" height="1"/>' * 2001),
    "ico no images": struct.pack("<HHH", 0, 1, 0) + b"\x00" * 40,
    "ico directory cut off": struct.pack("<HHH", 0, 1, 3) + b"\x00" * 20,
    "ico image outside file": struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, 9999, 22) + b"\x00" * 10,
    "ico empty image": struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, 0, 22) + b"\x00" * 10,
    "svg not xml": b"<svg><rect></svg>",
    "svg wrong root": b'<g xmlns="http://www.w3.org/2000/svg"/>',
    "svg javascript value": _svg(attrs='fill="javascript:alert(1)"'),
    "svg latin1": '<svg xmlns="http://www.w3.org/2000/svg"><title>é</title></svg>'.encode("latin-1"),
}


@pytest.mark.parametrize("name", list(BAD))
def test_unsafe_or_broken_images_are_refused(name):
    kind = "favicon" if name.startswith("ico ") else "logo"
    with pytest.raises(branding.ImageRefused):
        branding.inspect_image(BAD[name], kind)
    c = admin()
    r = save(c, **{kind: up("logo.png", BAD[name])})
    assert r.status_code == 200 and "Nothing was saved" in r.content.decode()
    assert not BrandImage.objects.exists() and not Branding.objects.exists()


def test_a_name_that_claims_png_is_judged_by_content():
    c = admin()
    r = save(c, logo=up("logo.png", b"<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>", "image/png"))
    assert r.status_code == 200 and not BrandImage.objects.exists()


def test_one_bad_file_saves_nothing_at_all():
    c = admin()
    r = save(c, name="Acme", logo=up("ok.png", png()), favicon=up("bad.svg", BAD["svg script"]))
    assert r.status_code == 200 and not BrandImage.objects.exists() and not Branding.objects.exists()


# ------------------------------------------------------------------ remove, reset, preview, serving
def test_remove_and_reset_restore_the_defaults():
    c = admin()
    save(c, name="Acme", accent="#1F4FBF", logo=up("l.png", png()), favicon=up("f.ico", ico()))
    save(c, name="Acme", accent="#1F4FBF", remove_logo="1")
    assert not BrandImage.objects.filter(kind="logo").exists() and BrandImage.objects.filter(kind="favicon").exists()
    assert anon().get("/brand/logo").status_code == 404
    r = c.post(reverse("appearance_reset"))
    assert r.status_code == 302
    assert not Branding.objects.exists() and not BrandImage.objects.exists()
    assert anon().get("/theme.css").content == b"" and "Acme" not in anon().get("/login/").content.decode()
    assert AuditLog.objects.filter(action="branding.reset").count() == 1
    c.post(reverse("appearance_reset"))   # nothing left: harmless, and not audited again
    assert AuditLog.objects.filter(action="branding.reset").count() == 1


def test_saving_the_defaults_on_a_fresh_system_creates_nothing():
    c = admin()
    r = save(c)
    assert r.status_code == 302 and not Branding.objects.exists() and not AuditLog.objects.filter(action="branding.updated").exists()
    assert "Nothing to reset" in c.post(reverse("appearance_reset"), follow=True).content.decode()


def test_saving_the_same_values_changes_and_audits_nothing():
    c = admin()
    save(c, name="Acme")
    save(c, name="Acme")
    assert AuditLog.objects.filter(action="branding.updated").count() == 1


def test_preview_shows_an_upload_without_storing_it():
    c = admin()
    r = c.post(reverse("appearance_preview"), {"name": "Preview Co", "accent": "#1F4FBF", "default_theme": "system", "default_density": "compact", "logo": up("l.png", png())})
    html = r.content.decode()
    assert r.status_code == 200 and "Preview Co" in html and "data:image/png;base64," in html and "#1F4FBF" in html
    assert not BrandImage.objects.exists() and not Branding.objects.exists()
    bad = c.post(reverse("appearance_preview"), {"accent": "red", "logo": up("l.png", BAD["svg script"])}).content.decode()
    assert "must look like" in bad and "not allowed" in bad
    assert c.get(reverse("appearance_preview")).status_code == 405


def test_images_are_not_served_on_the_mail_view_host():
    save(admin(), logo=up("l.png", png()))
    assert Client(HTTP_HOST="mailview.test").get("/brand/logo").status_code == 404


def test_unknown_image_kind_is_not_routable():
    assert anon().get("/brand/other").status_code == 404 and anon().get("/brand/logo").status_code == 404
    assert anon().post("/brand/logo").status_code == 405


def test_an_oversize_file_is_refused_for_its_size():
    assert len(BAD["too big"]) > branding.MAX_IMAGE
    with pytest.raises(branding.ImageRefused, match="larger than"):
        branding.inspect_image(BAD["too big"], "logo")
