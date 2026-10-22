from datetime import datetime, timedelta, timezone

import pytest
from django.urls import reverse

from apps.core.rbac import DELIVERABILITY_ADMIN, VIEWER
from apps.sesdata import metrics
from apps.sesdata.ingest import process_body

from . import factories as f
from .test_views import login

pytestmark = pytest.mark.django_db
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
SENT = (NOW - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
_n = iter(range(10_000))


def mail(to, outcome="delivery", from_domain="example.com", ts=SENT):
    """One message to one recipient that ends in `outcome` (delivery | bounce | complaint | send)."""
    mid = f"p{next(_n)}"
    ev = f.send(mid=mid, ts=ts, dest=(to,))
    ev["mail"]["source"] = f"x@{from_domain}"
    ev["mail"]["commonHeaders"]["from"] = [f"x@{from_domain}"]
    process_body(f.sns(ev), [f.TOPIC])
    later = {"delivery": f.delivery, "bounce": f.bounce, "complaint": f.complaint}.get(outcome)
    if later:
        kw = {"mid": mid, "ts": ts}
        e = later(**kw, **({"rcpts": (to,)} if outcome != "complaint" else {"rcpts": (to,)}))
        e["mail"]["source"] = f"x@{from_domain}"
        process_body(f.sns(e), [f.TOPIC])


def by_name(rows):
    return {r["name"]: r for r in rows}


# ---------------------------------------------------------------- classification
@pytest.mark.parametrize("domain,expected", [
    ("gmail.com", "Gmail"), ("GoogleMail.com", "Gmail"),
    ("outlook.com", "Microsoft"), ("hotmail.co.uk", "Microsoft"), ("live.com", "Microsoft"), ("outlook.in", "Microsoft"),
    ("yahoo.com", "Yahoo and AOL"), ("yahoo.co.in", "Yahoo and AOL"), ("ymail.com", "Yahoo and AOL"), ("aol.com", "Yahoo and AOL"),
    ("icloud.com", "Apple"), ("me.com", "Apple"),
    ("proton.me", "Proton"), ("protonmail.com", "Proton"),
    ("acme.io", "Other domains"), ("mygmail.com", "Other domains"), ("gmail.com.evil.example", "Other domains"),
    ("notoutlook.com", "Other domains"), ("", "Other domains"),
])
def test_provider_classification_is_exact_not_substring(domain, expected):
    assert metrics.provider_of(domain) == expected


# ---------------------------------------------------------------- counts
def test_providers_are_counted_by_recipient_outcome():
    for _ in range(8):
        mail("a@gmail.com")
    mail("b@gmail.com", "bounce")
    mail("c@googlemail.com", "complaint")
    for _ in range(3):
        mail("d@outlook.com")
    mail("e@acme.io", "bounce")
    mail("f@acme.io", "send")  # still in flight
    res = metrics.by_provider(24, NOW)
    p = by_name(res["providers"])
    assert p["Gmail"]["sent"] == 10 and p["Gmail"]["delivered"] == 8 and p["Gmail"]["bounced"] == 1 and p["Gmail"]["complained"] == 1
    assert p["Gmail"]["bounce_rate"] == pytest.approx(0.1) and p["Gmail"]["delivered_rate"] == pytest.approx(0.8)
    assert p["Microsoft"]["sent"] == 3 and p["Other domains"]["sent"] == 2 and p["Other domains"]["bounced"] == 1
    assert [r["name"] for r in res["providers"]] == ["Gmail", "Microsoft", "Other domains"]  # largest first


def test_the_window_excludes_older_mail():
    mail("old@gmail.com", "bounce", ts=(NOW - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    mail("new@gmail.com")
    assert by_name(metrics.by_provider(24, NOW)["providers"])["Gmail"]["sent"] == 1
    assert by_name(metrics.by_provider(48, NOW)["providers"])["Gmail"]["sent"] == 2


def test_problem_domains_are_ranked_and_only_domains_with_problems_appear():
    for _ in range(3):
        mail("x@bad.example", "bounce")
    mail("y@worse.example", "bounce")
    mail("y2@worse.example", "complaint")
    mail("z@worse.example", "bounce")
    mail("z2@worse.example", "bounce")  # worse.example: 4 problems, bad.example: 3
    for _ in range(5):
        mail("fine@good.example")
    mail("w@gmail.com", "bounce")
    doms = metrics.by_provider(24, NOW, top=3)["domains"]
    assert [d["name"] for d in doms] == ["worse.example", "bad.example", "gmail.com"]
    assert doms[0]["bounced"] == 3 and doms[0]["complained"] == 1 and doms[0]["provider"] == "Other domains"
    assert "good.example" not in [d["name"] for d in metrics.by_provider(24, NOW, top=10)["domains"]]


def test_a_tiny_sample_is_never_coloured(settings):
    mail("a@gmail.com", "bounce")  # 100% of 1
    row = by_name(metrics.by_provider(24, NOW)["providers"])["Gmail"]
    assert row["bounce_rate"] == 1.0 and row["bounce_tone"] == ""
    for _ in range(25):
        mail("b@outlook.com")
    for _ in range(5):
        mail("c@outlook.com", "bounce")  # 5/30 = 16.7%, above the page threshold
    assert by_name(metrics.by_provider(24, NOW)["providers"])["Microsoft"]["bounce_tone"] == "err"


def test_empty_data_returns_empty_lists():
    assert metrics.by_provider(24, NOW) == {"providers": [], "domains": []}


def test_an_address_without_an_at_sign_does_not_break_the_query():
    from apps.sesdata.models import MessageRecipient
    mail("a@gmail.com")
    MessageRecipient.objects.update(address_lower="not-an-address", address="not-an-address")
    assert by_name(metrics.by_provider(24, NOW)["providers"])["Other domains"]["sent"] == 1


# ---------------------------------------------------------------- scoping
def test_a_scoped_user_only_sees_recipients_of_their_own_from_domains():
    mail("a@gmail.com", from_domain="example.com")
    mail("secret@customer-of-other-brand.com", "bounce", from_domain="other-brand.com")
    scoped = metrics.by_provider(24, NOW, scope_domains=["example.com"])
    assert [r["name"] for r in scoped["providers"]] == ["Gmail"]
    assert scoped["domains"] == []                     # the bounce belongs to another brand
    unscoped = metrics.by_provider(24, NOW)
    assert "customer-of-other-brand.com" in [d["name"] for d in unscoped["domains"]]


# ---------------------------------------------------------------- the dashboard
def test_dashboard_shows_the_breakdown_and_respects_the_window_and_scope():
    now = datetime.now(timezone.utc)
    recent = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for _ in range(3):
        mail("a@gmail.com", ts=recent)
    mail("lost@bad-domain.example", "bounce", ts=recent)
    mail("hidden@other-customer.example", "bounce", from_domain="other-brand.com", ts=recent)
    c, _ = login(VIEWER, "v@example.com")
    html = c.get(reverse("dashboard")).content.decode()
    assert "By recipient provider" in html and "Gmail" in html and "bad-domain.example" in html and "other-customer.example" in html
    c2, _ = login(DELIVERABILITY_ADMIN, "scoped@example.com", scope_domains=["example.com"])
    html2 = c2.get(reverse("dashboard")).content.decode()
    assert "bad-domain.example" in html2 and "other-customer.example" not in html2


def test_dashboard_renders_with_no_mail():
    c, _ = login(VIEWER, "v@example.com")
    html = c.get(reverse("dashboard")).content.decode()
    assert "No recipients in this period" in html and "No problem domains" in html
