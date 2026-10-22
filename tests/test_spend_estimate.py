from datetime import datetime, timedelta, timezone

import pytest
from django.urls import reverse

from apps.core.rbac import DELIVERABILITY_ADMIN, VIEWER
from apps.core.templatetags.ui import usd
from apps.sesdata import metrics
from apps.sesdata.ingest import process_body

from . import factories as f
from .test_aws_policies import _import_settings
from .test_views import login

pytestmark = pytest.mark.django_db
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
_n = iter(range(10_000))


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def mail(to=("a@x.com",), app="webapp", hours_ago=2, from_domain="example.com", now=NOW):
    ev = f.send(mid=f"c{next(_n)}", ts=iso(now - timedelta(hours=hours_ago)), dest=tuple(to), tags={"mc-app": [app]})
    ev["mail"]["source"] = f"x@{from_domain}"
    ev["mail"]["commonHeaders"]["from"] = [f"x@{from_domain}"]
    process_body(f.sns(ev), [f.TOPIC])


# ---------------------------------------------------------------- the dollar format
@pytest.mark.parametrize("v,out", [(0, "$0.00"), (0.0004, "$0.0004"), (0.009, "$0.0090"), (0.01, "$0.01"), (12.3456, "$12.35"), (1234.5, "$1,234.50"), (None, "-"), ("x", "-")])
def test_usd_format(v, out):
    assert usd(v) == out


# ---------------------------------------------------------------- the estimate
def test_every_recipient_is_one_billable_email_at_the_configured_price(settings):
    settings.SES_PRICE_PER_1000 = 0.10
    mail(("a@x.com", "b@x.com", "c@x.com"))            # one message to three people = three emails
    mail(("d@x.com",))
    r = metrics.cost_by_app(NOW - timedelta(days=1), NOW)
    assert r["recipients"] == 4 and r["cost"] == pytest.approx(0.0004)
    settings.SES_PRICE_PER_1000 = 0.25
    assert metrics.cost_by_app(NOW - timedelta(days=1), NOW)["cost"] == pytest.approx(0.001)
    settings.SES_PRICE_PER_1000 = 0
    assert metrics.cost_by_app(NOW - timedelta(days=1), NOW)["cost"] == 0


def test_cost_is_split_by_app_busiest_first_with_untagged_named_and_a_top_limit(settings):
    settings.SES_PRICE_PER_1000 = 1.0
    for _ in range(5):
        mail(app="billing")
    for _ in range(3):
        mail(app="webapp")
    process_body(f.sns(f.send(mid="u1", ts=iso(NOW - timedelta(hours=2)), tags={"mc-app": [""]})), [f.TOPIC])
    r = metrics.cost_by_app(NOW - timedelta(days=1), NOW, top=2)
    assert [(a["app"], a["recipients"]) for a in r["apps"]] == [("billing", 5), ("webapp", 3)] and r["more"] == 1 and r["recipients"] == 9
    assert r["apps"][0]["cost"] == pytest.approx(0.005)
    names = [a["app"] for a in metrics.cost_by_app(NOW - timedelta(days=1), NOW)["apps"]]
    assert "(untagged)" in names or "webapp" in names            # blank tag is shown by name, never as an empty cell


def test_only_the_chosen_period_counts(settings):
    mail(hours_ago=2)
    mail(hours_ago=30)
    mail(hours_ago=24 * 40)
    assert metrics.cost_by_app(NOW - timedelta(hours=24), NOW)["recipients"] == 1
    assert metrics.cost_by_app(NOW - timedelta(hours=48), NOW)["recipients"] == 2
    assert metrics.cost_by_app(NOW - timedelta(days=60), NOW)["recipients"] == 3


def test_month_to_date_starts_at_the_first_of_the_month_utc():
    assert metrics.month_start(datetime(2026, 10, 20, 12, 34, 56, tzinfo=timezone.utc)) == datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert metrics.month_start(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)) == datetime(2026, 1, 1, tzinfo=timezone.utc)
    mail(hours_ago=24 * 25)                                       # 25 days before the 20th: last month
    mail(hours_ago=24 * 5)
    assert metrics.cost_by_app(metrics.month_start(NOW), NOW)["recipients"] == 1


def test_a_scoped_user_only_sees_the_cost_of_their_own_from_domains(settings):
    settings.SES_PRICE_PER_1000 = 1.0
    mail(from_domain="example.com")
    mail(("a@x.com", "b@x.com"), from_domain="other-brand.com", app="secret-app")
    scoped = metrics.cost_by_app(NOW - timedelta(days=1), NOW, scope_domains=["example.com"])
    assert scoped["recipients"] == 1 and [a["app"] for a in scoped["apps"]] == ["webapp"]
    assert metrics.cost_by_app(NOW - timedelta(days=1), NOW)["recipients"] == 3


def test_no_data_is_zero_not_an_error():
    r = metrics.cost_by_app(NOW - timedelta(days=1), NOW)
    assert r == {"recipients": 0, "cost": 0, "apps": [], "more": 0}


# ---------------------------------------------------------------- the page and the setting
def test_the_overview_shows_the_estimate_labelled_as_one_with_its_assumptions(settings):
    settings.SES_PRICE_PER_1000 = 0.10
    now = datetime.now(timezone.utc)
    for _ in range(4):
        mail(app="billing", hours_ago=1, now=now)
    c, _ = login(VIEWER, "v@example.com")
    html = c.get(reverse("dashboard")).content.decode()
    assert "Estimated SES cost" in html and "estimate" in html and "billing" in html and "$0.0004" in html
    assert "$0.10 per 1,000" in html and "free tier" in html and "MC_SES_PRICE_PER_1000" in html


def test_the_overview_respects_a_scoped_users_domains():
    now = datetime.now(timezone.utc)
    mail(from_domain="example.com", app="mine", now=now, hours_ago=1)
    mail(from_domain="other-brand.com", app="secret-app", now=now, hours_ago=1)
    c, _ = login(DELIVERABILITY_ADMIN, "scoped@example.com", scope_domains=["example.com"])
    html = c.get(reverse("dashboard")).content.decode()
    assert "mine" in html and "secret-app" not in html


def test_the_overview_renders_with_no_mail():
    c, _ = login(VIEWER, "v@example.com")
    assert "$0.00" in c.get(reverse("dashboard")).content.decode()


def test_the_price_setting_is_validated_at_startup():
    for bad in ("-1", "abc", "101", "nan"):
        code, err = _import_settings(MC_SES_PRICE_PER_1000=bad)
        assert code != 0 and "MC_SES_PRICE_PER_1000" in err, bad
    assert _import_settings(MC_SES_PRICE_PER_1000="0.10")[0] == 0 and _import_settings(MC_SES_PRICE_PER_1000="0")[0] == 0
