import pytest
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, SUPPORT
from apps.core.scope import scoped_alerts, scoped_suppression
from apps.sesdata.ingest import process_body
from apps.sesdata.models import Alert, SuppressionChange, SuppressionEntry

from . import factories as f
from .test_views import login

pytestmark = pytest.mark.django_db
MINE, THEIRS = "example.com", "other-brand.com"


def mail(to, from_domain, mid):
    ev = f.send(mid=mid, dest=(to,))
    ev["mail"]["source"] = f"x@{from_domain}"
    ev["mail"]["commonHeaders"]["from"] = [f"x@{from_domain}"]
    process_body(f.sns(ev), [f.TOPIC])


def sup(addr, region="ap-south-1"):
    SuppressionEntry.objects.create(aws_account_id="1", region=region, address=addr, address_lower=addr.lower(), reason="BOUNCE")
    SuppressionChange.objects.create(aws_account_id="1", region=region, address=addr, change="seen_added")


def alert(key, title, resolved=False):
    from django.utils import timezone
    return Alert.objects.create(key=key, severity="warn", title=title, resolved_at=timezone.now() if resolved else None)


@pytest.fixture
def world():
    mail("mine@customer-a.com", MINE, "m1")
    mail("Theirs@Customer-B.com", THEIRS, "m2")
    sup("mine@customer-a.com"), sup("Theirs@Customer-B.com"), sup("never-emailed@nowhere.com")
    alert("dns:example.com:spf", "DNS SPF problem for example.com")
    alert("dns:other-brand.com:dkim", "DNS DKIM problem for other-brand.com")
    alert("app_bounce:secret-app:ab12cd34", "Bounce rate 9% for app secret-app")
    alert("bounce_rate", "Bounce rate 3% (estimate, 24h)")
    alert("quota:ap-south-1", "Daily quota 85% used in ap-south-1")
    alert("silent:my-set", "No SES events for config set my-set in 18 hours+")
    alert("dns:other-brand.com:spf", "Old DNS problem for other-brand.com", resolved=True)
    alert("brand-new-kind:x", "A kind of alert nobody has decided how to scope")


def scoped(role=DELIVERABILITY_ADMIN, step_up=True):
    return login(role, "scoped@example.com", scope_domains=[MINE], step_up=step_up)


# ---------------------------------------------------------------- alerts
def test_a_scoped_user_sees_account_level_alerts_and_their_own_dns_alerts_only(world):
    c, u = scoped()
    keys = set(scoped_alerts(u, Alert.objects.all()).values_list("key", flat=True))
    assert keys == {"dns:example.com:spf", "bounce_rate", "quota:ap-south-1", "silent:my-set"}


def test_unknown_alert_kinds_and_per_app_alerts_are_hidden_by_default(world):
    c, u = scoped()
    keys = set(scoped_alerts(u, Alert.objects.all()).values_list("key", flat=True))
    assert not any(k.startswith(("app_", "brand-new-kind")) for k in keys)


def test_malformed_dns_keys_are_hidden_rather_than_guessed_at(world):
    alert("dns:", "weird"), alert("dns:example.com", "also weird")
    _, u = scoped()
    keys = set(scoped_alerts(u, Alert.objects.all()).values_list("key", flat=True))
    assert "dns:" not in keys and "dns:example.com" not in keys


def test_an_unscoped_user_sees_everything(world):
    c, u = login(DELIVERABILITY_ADMIN, "all@example.com")
    assert scoped_alerts(u, Alert.objects.all()).count() == Alert.objects.count()


def test_the_alerts_page_the_overview_strip_and_the_nav_badge_follow_the_scope(world):
    c, _ = scoped()
    for name in ("alerts", "dashboard"):
        html = c.get(reverse(name)).content.decode()
        assert "other-brand.com" not in html and "secret-app" not in html and "nobody has decided" not in html, name
    assert "DNS SPF problem for example.com" in c.get(reverse("alerts")).content.decode()
    # the badge counts only what they can see: 4 open alerts are visible to them out of 7 open ones overall
    from apps.core.context import console_context
    from django.test import RequestFactory
    req = RequestFactory().get("/")
    req.user = c.session and __import__("apps.accounts.models", fromlist=["User"]).User.objects.get(email="scoped@example.com")
    req.session = {}
    badge = [i["count"] for g in console_context(req)["nav_groups"] for i in g["items"] if i["label"] == "Alerts"]
    assert badge == [4]


# ---------------------------------------------------------------- suppression list
def test_a_scoped_user_sees_only_suppressed_addresses_that_their_own_domains_mailed(world):
    c, u = scoped()
    shown = set(scoped_suppression(u, SuppressionEntry.objects.all()).values_list("address", flat=True))
    assert shown == {"mine@customer-a.com"}                       # not the other brand's customer, and not an address nobody here mailed


def test_matching_ignores_case_in_the_address(world):
    mail("THEIRS@customer-b.com", MINE, "m3")                     # now one of OUR domains has mailed that customer too
    _, u = scoped()
    assert "Theirs@Customer-B.com" in set(scoped_suppression(u, SuppressionEntry.objects.all()).values_list("address", flat=True))


def test_the_suppression_page_its_count_its_history_and_its_search_are_all_scoped(world):
    c, _ = scoped()
    html = c.get(reverse("suppression")).content.decode()
    assert "mine@customer-a.com" in html and "customer-b" not in html.lower() and "never-emailed" not in html
    assert "1 addresses in" in html                                # the header count is the scoped one
    assert "customer-b" not in c.get(reverse("suppression") + "?q=theirs").content.decode().lower()


def test_the_suppression_export_is_scoped_and_audited_with_the_scoped_count(world):
    c, _ = scoped()
    r = c.get(reverse("suppression_export"))
    body = b"".join(r.streaming_content).decode()
    assert "mine@customer-a.com" in body and "customer-b" not in body.lower() and "never-emailed" not in body
    assert AuditLog.objects.get(action="export.suppression").details["addresses"] == 1


def test_a_scoped_person_cannot_remove_an_address_they_cannot_see(world, monkeypatch):
    called = []
    from types import SimpleNamespace
    monkeypatch.setattr("apps.approvals.service.request_action", lambda *a, **k: (called.append(a), SimpleNamespace(state="pending", result={}))[1])
    c, _ = scoped(SUPPORT)
    r = c.post(reverse("suppression_remove"), {"addresses": "Theirs@Customer-B.com, mine@customer-a.com", "reason": "x"})
    assert r.status_code == 302 and not called
    assert "Not on your list: Theirs@Customer-B.com" in c.get(reverse("suppression")).content.decode()
    c.post(reverse("suppression_remove"), {"addresses": "mine@customer-a.com", "reason": "x"})
    assert len(called) == 1                                        # their own address goes through to the normal flow


def test_an_unscoped_user_is_unaffected(world):
    c, u = login(SUPPORT, "all@example.com", step_up=True)
    assert scoped_suppression(u, SuppressionEntry.objects.all()).count() == 3
    assert "Theirs@Customer-B.com" in c.get(reverse("suppression")).content.decode()
