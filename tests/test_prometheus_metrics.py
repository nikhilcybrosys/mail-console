import logging
import math
import re
from datetime import datetime, timedelta, timezone

import pytest
from django.test import Client

from apps.approvals.models import ApprovalRequest
from apps.core import prom
from apps.core import views as core_views
from apps.sesdata import promstats
from apps.sesdata.ingest import process_body
from apps.sesdata.models import AccountSnapshot, Alert, SuppressionEntry

from . import factories as f
from .test_aws_policies import _import_settings
from .test_views import login

pytestmark = pytest.mark.django_db
TOKEN = "k" * 40
RECENT = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
_n = iter(range(10_000))


@pytest.fixture(autouse=True)
def fresh_cache():
    core_views._METRICS_CACHE.update(at=0.0, body="")


@pytest.fixture
def on(settings):
    settings.METRICS_TOKEN, settings.METRICS_CACHE_SECONDS = TOKEN, 0
    return settings


def get(path="/metrics", token=TOKEN, host="console.test", **extra):
    headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
    return Client(HTTP_HOST=host).get(path, **headers, **extra)


def mail(outcome=None, app="webapp", to="a@x.com", subject="Hello"):
    mid = f"m{next(_n)}"
    process_body(f.sns(f.send(mid=mid, ts=RECENT, dest=(to,), subject=subject, tags={"mc-app": [app]})), [f.TOPIC])
    if outcome == "bounce":
        process_body(f.sns(f.bounce(mid=mid, ts=RECENT, rcpts=(to,), tags={"mc-app": [app]}, feedback=f"fb{mid}")), [f.TOPIC])
    if outcome == "delivery":
        process_body(f.sns(f.delivery(mid=mid, ts=RECENT, rcpts=(to,), tags={"mc-app": [app]})), [f.TOPIC])
    return mid


def samples(body):
    """{(name, frozenset(labels)): value} from an exposition document, parsed strictly."""
    out = {}
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{((?:[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\.)*",?)*)\})? (\S+)', line)
        assert m, f"not valid exposition syntax: {line!r}"
        labels = frozenset(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\.)*)"', m[2] or ""))
        out[(m[1], labels)] = float(m[3].replace("+Inf", "inf").replace("NaN", "nan"))
    return out


def value(body, name, **labels):
    return samples(body)[(name, frozenset((k, str(v)) for k, v in labels.items()))]


# ---------------------------------------------------------------- the writer
def test_render_escapes_labels_help_and_formats_numbers():
    fam = prom.Family("demo_total", 'Counts "things"\nline two \\ backslash', "counter")
    fam.add(3, who='quote " back\\slash\nnewline')
    fam.add(True, flag="y")
    fam.add(0.25, flag="n")
    fam.add(float("nan"), x="nan")
    fam.add(float("inf"), x="inf")
    fam.add(float("-inf"), x="neg")
    body = prom.render([fam])
    assert body.endswith("\n") and "\n\n" not in body
    assert '# HELP demo_total Counts "things"\\nline two \\\\ backslash' in body and "# TYPE demo_total counter" in body
    assert 'demo_total{who="quote \\" back\\\\slash\\nnewline"} 3' in body
    assert 'demo_total{flag="y"} 1' in body and 'demo_total{flag="n"} 0.25' in body
    assert 'x="nan"} NaN' in body and 'x="inf"} +Inf' in body and 'x="neg"} -Inf' in body
    assert len(samples(body)) == 6          # and a strict parser reads every line


def test_render_skips_empty_families_and_rejects_bad_names():
    assert prom.render([prom.Family("nothing_here", "x")]) == "\n"
    for bad in ("1starts_with_digit", "has space", "has-dash", ""):
        with pytest.raises(ValueError):
            prom.Family(bad, "x")
    with pytest.raises(ValueError):
        prom.Family("ok_name", "x", "histogram")
    for bad_label in ("bad-label", "1x", "__reserved"):
        with pytest.raises(ValueError):
            prom.Family("ok_name", "x").add(1, **{bad_label: "v"})


# ---------------------------------------------------------------- access: nothing leaks without the token
def test_endpoint_does_not_exist_until_a_token_is_configured(settings):
    settings.METRICS_TOKEN = ""
    assert get().status_code == 404
    assert get(token="anything").status_code == 404           # a header does not switch it on


def test_missing_wrong_or_misplaced_tokens_get_401_and_no_data(on):
    for r in (get(token=None), get(token="wrong" * 8), get(token=TOKEN[:-1]), get(token=TOKEN + "x")):
        assert r.status_code == 401 and r["WWW-Authenticate"] == "Bearer" and b"mailconsole_" not in r.content
    assert get(token=None, **{}).status_code == 401
    assert Client(HTTP_HOST="console.test").get(f"/metrics?token={TOKEN}").status_code == 401        # a query-string token is not accepted (it ends up in logs)
    assert Client(HTTP_HOST="console.test").get("/metrics", HTTP_AUTHORIZATION=f"Basic {TOKEN}").status_code == 401
    assert Client(HTTP_HOST="console.test").get("/metrics", HTTP_AUTHORIZATION=TOKEN).status_code == 401


def test_a_signed_in_person_without_the_token_is_not_enough(on):
    c, _ = login("security_admin", "s@example.com", step_up=True)
    assert c.get("/metrics").status_code == 401


def test_correct_token_works_with_any_bearer_casing_and_only_for_get(on):
    r = get()
    assert r.status_code == 200 and r["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8" and r["Cache-Control"] == "no-store"
    assert "Set-Cookie" not in r.headers
    assert Client(HTTP_HOST="console.test").get("/metrics", HTTP_AUTHORIZATION=f"bearer {TOKEN}").status_code == 200
    assert Client(HTTP_HOST="console.test").post("/metrics", HTTP_AUTHORIZATION=f"Bearer {TOKEN}").status_code == 405
    assert get("/metrics/").status_code == 404                # exactly /metrics, no trailing-slash alias


def test_a_rejected_scrape_is_logged_without_the_token(on, caplog):
    with caplog.at_level(logging.WARNING):
        get(token="guess" * 8)
    assert any("rejected a scrape" in r.message for r in caplog.records)
    assert "guess" not in caplog.text and TOKEN not in caplog.text


def test_the_mailview_origin_never_serves_metrics(on):
    assert get(host="mailview.test").status_code == 404


def test_short_tokens_are_refused_at_startup():
    for bad in ("short", "x" * 31):
        code, err = _import_settings(MC_METRICS_TOKEN=bad)
        assert code != 0 and "MC_METRICS_TOKEN" in err, bad
    assert _import_settings(MC_METRICS_TOKEN="x" * 32)[0] == 0


# ---------------------------------------------------------------- content
def test_event_counts_per_type_and_per_app(on):
    for _ in range(3):
        mail("delivery", app="billing")
    mail("bounce", app="billing")
    mail(app="webapp")
    body = get().content.decode()
    assert value(body, "mailconsole_events_24h", event_type="send") == 5
    assert value(body, "mailconsole_events_24h", event_type="delivery") == 3 and value(body, "mailconsole_events_24h", event_type="bounce") == 1
    assert value(body, "mailconsole_app_events_24h", app="billing", event_type="send") == 4
    assert value(body, "mailconsole_app_events_24h", app="billing", event_type="bounce") == 1
    assert value(body, "mailconsole_app_events_24h", app="webapp", event_type="complaint") == 0   # zeros are present, so rate() works
    assert value(body, "mailconsole_reputation_sample_24h") == 5 and value(body, "mailconsole_reputation_bounce_rate_24h") == pytest.approx(0.2)
    assert value(body, "mailconsole_last_event_timestamp_seconds") > 1_700_000_000


def test_account_state_alerts_approvals_and_suppression(on):
    AccountSnapshot.objects.create(aws_account_id="1", region="ap-south-1", production_access=True, sending_enabled=True,
                                   enforcement_status="HEALTHY", max_24h_send=50000.0, sent_last_24h=500.0)
    AccountSnapshot.objects.create(aws_account_id="1", region="ap-south-1", production_access=True, sending_enabled=False,
                                   enforcement_status="PROBATION", max_24h_send=50000.0, sent_last_24h=1000.0)   # newest wins
    AccountSnapshot.objects.create(aws_account_id="1", region="us-east-1", production_access=False, sending_enabled=True, max_24h_send=0.0)
    for i in range(3):
        SuppressionEntry.objects.create(aws_account_id="1", region="ap-south-1", address=f"a{i}@x.com", address_lower=f"a{i}@x.com", reason="BOUNCE")
    Alert.objects.create(key="a", severity="warn", title="t")
    Alert.objects.create(key="b", severity="warn", title="t")
    Alert.objects.create(key="c", severity="page", title="t")
    Alert.objects.create(key="d", severity="warn", title="t", resolved_at=datetime.now(timezone.utc))   # resolved: not counted
    ApprovalRequest.objects.create(action="x", params_hash="h", region="ap-south-1", requested_by=login("viewer", "r@example.com")[1], state="pending",
                                   expires_at=datetime.now(timezone.utc) + timedelta(hours=24))
    body = get().content.decode()
    assert value(body, "mailconsole_ses_sending_enabled", region="ap-south-1") == 0
    assert value(body, "mailconsole_ses_enforcement_healthy", region="ap-south-1") == 0
    assert value(body, "mailconsole_ses_quota_used_ratio", region="ap-south-1") == pytest.approx(0.02)
    assert value(body, "mailconsole_ses_production_access", region="us-east-1") == 0
    assert value(body, "mailconsole_ses_quota_used_ratio", region="us-east-1") == 0          # no quota: no division by zero
    assert value(body, "mailconsole_suppression_entries", region="ap-south-1") == 3
    assert value(body, "mailconsole_alerts_open", severity="warn") == 2 and value(body, "mailconsole_alerts_open", severity="page") == 1
    assert value(body, "mailconsole_approvals_pending") == 1
    assert value(body, "mailconsole_last_sync_timestamp_seconds", region="ap-south-1") > 1_700_000_000


def test_an_empty_database_still_produces_a_valid_document(on):
    body = get().content.decode()
    s = samples(body)
    assert s[("mailconsole_alerts_open", frozenset({("severity", "warn")}))] == 0 and s[("mailconsole_approvals_pending", frozenset())] == 0
    assert not any(math.isnan(v) for v in s.values())


def test_no_addresses_subjects_or_message_ids_ever_appear(on):
    mid = mail("bounce", to="very.private.person@secret-customer.example", subject="Your salary review")
    SuppressionEntry.objects.create(aws_account_id="1", region="ap-south-1", address="leaked.address@x.com", address_lower="leaked.address@x.com", reason="BOUNCE")
    Alert.objects.create(key="k", severity="warn", title="Bounce rate for secret-customer.example", detail="very.private.person@secret-customer.example")
    body = get().content.decode()
    for secret in ("very.private.person", "secret-customer", "salary", "leaked.address", mid, "@"):
        assert secret not in body, secret


def test_label_cardinality_is_capped_at_the_busiest_apps(on):
    for i in range(promstats.TOP_APPS + 10):
        for _ in range(1 + (i % 3)):
            mail(app=f"app-{i:03d}")
    mail(app="app-quiet")
    apps = {dict(k[1])["app"] for k in samples(get().content.decode()) if k[0] == "mailconsole_app_events_24h"}
    assert len(apps) == promstats.TOP_APPS


def test_untagged_mail_gets_a_clear_label_and_hostile_app_names_stay_valid(on):
    process_body(f.sns(f.send(mid="u1", ts=RECENT, tags={"mc-app": [""]})), [f.TOPIC])
    mail(app='evil"app\nname\\x')
    body = get().content.decode()
    samples(body)                                             # strict parse: the hostile name did not break the document
    assert 'app="evil\\"app\\nname\\\\x"' in body


# ---------------------------------------------------------------- caching
def test_scrapes_within_the_ttl_reuse_one_database_pass(settings):
    settings.METRICS_TOKEN, settings.METRICS_CACHE_SECONDS = TOKEN, 3600
    mail()
    first = get().content
    mail()
    assert get().content == first                              # cached: the second mail is not visible yet
    settings.METRICS_CACHE_SECONDS = 0
    assert get().content != first                              # ttl elapsed: fresh data


def test_the_cache_never_lets_an_unauthenticated_request_see_data(settings):
    settings.METRICS_TOKEN, settings.METRICS_CACHE_SECONDS = TOKEN, 3600
    get()                                                      # warm the cache
    r = get(token=None)
    assert r.status_code == 401 and b"mailconsole_" not in r.content
