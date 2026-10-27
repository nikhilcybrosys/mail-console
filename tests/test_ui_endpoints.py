import time

import pytest
from django.test import Client
from django.urls import reverse

from apps.accounts.models import User
from apps.core.views import contrast_with_white
from apps.sesdata.ingest import process_body
from apps.sesdata.models import Message

from . import factories as f

pytestmark = pytest.mark.django_db
TOPICS = [f.TOPIC]


def login(role="viewer", email=None, **extra):
    u = User.objects.create_user(email or f"{role}@x.com", role=role, **extra)
    c = Client(HTTP_HOST="console.test")
    c.force_login(u)
    s = c.session
    s["session_started"] = s["last_seen"] = s["login_at"] = time.time()
    s.save()
    return c


def seed(n=3):
    for i in range(n):
        process_body(f.sns(f.send(mid=f"mid{i:06d}abcdef", dest=(f"user{i}@acme.io",), subject=f"Subject {i}")), TOPICS)


def test_messages_full_page_vs_htmx_fragment():
    seed()
    c = login()
    full = c.get(reverse("messages")).content.decode()
    assert "<html" in full and 'id="results"' in full
    frag = c.get(reverse("messages"), HTTP_HX_REQUEST="true", HTTP_HX_TARGET="results")
    body = frag.content.decode()
    assert "<html" not in body and "Subject 1" in body
    assert "HX-Request" in frag["Vary"] and "HX-Target" in frag["Vary"]


def test_sort_parameter_is_whitelisted():
    seed()
    c = login()
    for evil in ("sent_at;DROP TABLE x", "-id", "recipients__address", "__class__", "pk"):
        assert c.get(reverse("messages"), {"sort": evil, "dir": "asc"}).status_code == 200
    r = c.get(reverse("messages"), {"sort": "subject", "dir": "asc"}).content.decode()
    assert r.index("Subject 0") < r.index("Subject 2")
    r = c.get(reverse("messages"), {"sort": "subject", "dir": "desc"}).content.decode()
    assert r.index("Subject 2") < r.index("Subject 0")


def test_status_tab_counts_and_filter_chips():
    seed(2)
    process_body(f.sns(f.bounce(mid="mid000000abcdef", rcpts=("user0@acme.io",), dest=("user0@acme.io",))), TOPICS)
    c = login()
    html = c.get(reverse("messages"), {"state": "bounce", "app": "webapp"}).content.decode()
    assert "Subject 0" in html and "Subject 1" not in html
    assert "Remove filter" in html and "webapp" in html


def test_drawer_returns_fragment_and_enforces_scope():
    seed(1)
    m = Message.objects.get()
    ok = login("viewer", "a@x.com")
    r = ok.get(reverse("message_drawer", args=[m.pk]), HTTP_HX_REQUEST="true", HTTP_HX_TARGET="drawer-body")
    html = r.content.decode()
    assert r.status_code == 200 and "<html" not in html and "Timeline" in html and m.ses_message_id in html
    other = login("viewer", "b@x.com", scope_domains=["other.com"])
    assert other.get(reverse("message_drawer", args=[m.pk])).status_code == 404
    assert Client(HTTP_HOST="console.test").get(reverse("message_drawer", args=[m.pk])).status_code == 302


def test_drawer_explains_a_bounce():
    for e in (f.send(), f.bounce(sub="OnAccountSuppressionList")):
        process_body(f.sns(e), TOPICS)
    html = login().get(reverse("message_drawer", args=[Message.objects.get().pk])).content.decode()
    assert "YOUR account suppression list" in html and "550 5.1.1" in html and "remove it from the suppression list" in html


def test_palette_groups_and_scope():
    seed(2)
    c = login()
    r = c.get(reverse("palette"), {"q": "user1@"}, HTTP_HX_REQUEST="true", HTTP_HX_TARGET="palette-results").content.decode()
    assert "user1@acme.io" in r and "Check suppression" in r and "<html" not in r
    r = c.get(reverse("palette"), {"q": "mid000001abc"}).content.decode()
    assert "mid000001abcdef" in r and "/messages/?open=" in r
    scoped = login("viewer", "s@x.com", scope_domains=["other.com"])
    assert "user1@acme.io" not in scoped.get(reverse("palette"), {"q": "user1@"}).content.decode()
    nav = c.get(reverse("palette"), {"q": "supp"}).content.decode()
    assert "Suppression list" in nav and "Audit log" not in nav  # viewer role: no audit entry


def test_palette_hides_governance_pages_from_viewers():
    html = login("viewer").get(reverse("palette")).content.decode()
    assert "Audit log" not in html and "Inbox" not in html
    assert "Audit log" in login("support", "sup@x.com").get(reverse("palette")).content.decode()


def test_search_enter_jumps_to_a_message_drawer():
    seed(1)
    m = Message.objects.get()
    r = login().get(reverse("search"), {"q": m.ses_message_id[:14]})
    assert r.status_code == 302 and r["Location"] == f"/messages/?open={m.pk}"


def test_theme_css_empty_by_default_and_validates_accent(settings):
    c = Client(HTTP_HOST="console.test")
    assert c.get("/theme.css").content == b""
    settings.BRAND_ACCENT = "#1F4FBF"
    css = c.get("/theme.css").content.decode()
    assert "--accent:#1F4FBF" in css and "--btn-primary-hover:" in css and css.count("{") == 3
    for bad in ("red", "#12", "#1F4FBF;} body{display:none", "url(//evil)", "#FFFF00"):  # last: yellow fails 4.5:1 with white
        settings.BRAND_ACCENT = bad
        assert c.get("/theme.css").content == b"", bad


def test_contrast_helper_matches_known_values():
    assert contrast_with_white("#000000") == pytest.approx(21.0, rel=0.01)
    assert contrast_with_white("#CF4430") >= 4.5


def test_navigation_is_capability_filtered_with_live_counts():
    from apps.sesdata.models import Alert
    Alert.objects.create(key="k", severity="warn", title="t")
    viewer = login("viewer").get(reverse("dashboard")).content.decode()
    assert "Audit log" not in viewer and "Users and roles" not in viewer and "Approvals" not in viewer
    admin = login("security_admin", "adm@x.com").get(reverse("dashboard")).content.decode()
    assert "Audit log" in admin and "Users and roles" in admin and "Approvals" in admin
    assert 'class="count">1<' in viewer  # open alert badge on the Alerts nav item


def test_error_pages_render_branded_and_without_leaking():
    c = login()
    r = c.get("/does-not-exist/")
    assert r.status_code == 404 and "Page not found" in r.content.decode()
    r = c.get(reverse("audit"))
    assert r.status_code == 403 and "don" in r.content.decode()


def test_login_page_is_provider_neutral_and_themeable(settings):
    settings.OIDC_PROVIDER_NAME = "Okta"
    settings.BRAND_NAME = "Acme Mail"
    html = Client(HTTP_HOST="console.test").get("/login/").content.decode()
    assert "Continue with Okta" in html and "Acme Mail" in html and "Google" not in html


def test_ago_handles_past_and_future_times():
    from datetime import timedelta
    from django.utils import timezone
    from apps.core.templatetags.ui import ago
    now = timezone.now()
    assert "5m ago" in ago(now - timedelta(minutes=5, seconds=2))
    assert "3h ago" in ago(now - timedelta(hours=3, seconds=5))
    assert "in 23h" in ago(now + timedelta(hours=23, minutes=59))   # approval expiry used to read "just now"
    assert "in 2d" in ago(now + timedelta(days=2, minutes=1))
    assert "just now" in ago(now)
    assert ago(None) == "-"
