import csv
import io
from datetime import datetime, timedelta, timezone

import pytest
from django.http import QueryDict
from django.urls import reverse

from apps.accounts.models import SavedView
from apps.audit.models import AuditLog
from apps.console import exports
from apps.core.rbac import DELIVERABILITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata.ingest import process_body
from apps.sesdata.models import SuppressionEntry

from . import factories as f
from .test_aws_policies import _import_settings
from .test_views import login

pytestmark = pytest.mark.django_db
SENT = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
_n = iter(range(10_000))


def mail(to=("a@x.com",), subject="Hello", app="webapp", from_domain="example.com", bounce=None, category=None):
    mid = f"e{next(_n)}"
    ev = f.send(mid=mid, ts=SENT, dest=tuple(to), subject=subject, tags={"mc-app": [app]})
    ev["mail"]["source"] = f"x@{from_domain}"
    ev["mail"]["commonHeaders"]["from"] = [f"x@{from_domain}"]
    process_body(f.sns(ev), [f.TOPIC])
    if bounce:
        b = f.bounce(mid=mid, ts=SENT, rcpts=(bounce,), tags={"mc-app": [app]})
        b["mail"]["source"] = f"x@{from_domain}"
        process_body(f.sns(b), [f.TOPIC])
    return mid


def read(resp):
    text = b"".join(resp.streaming_content).decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text)))


# ---------------------------------------------------------------- CSV safety
@pytest.mark.parametrize("raw,expected", [
    ("=1+1", "'=1+1"), ("+919999999999", "'+919999999999"), ("-2+3", "'-2+3"), ("@SUM(A1)", "'@SUM(A1)"),
    ("\t=cmd", "'\t=cmd"), ("\r=cmd", "'\r=cmd"),
    ("hello", "hello"), ("a=b", "a=b"), ("", ""), (None, ""), (42, "42"),
])
def test_csv_safe_neutralises_formulas_and_leaves_text_alone(raw, expected):
    assert exports.csv_safe(raw) == expected


# ---------------------------------------------------------------- the message export
def test_export_has_one_row_per_recipient_with_a_header_and_utf8_bom():
    mail(to=("a@gmail.com", "b@outlook.com"), subject="Welcome", bounce="b@outlook.com")
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    r = c.get(reverse("messages_export"))
    raw = b"".join(r.streaming_content)
    assert r.status_code == 200 and r["Content-Type"].startswith("text/csv") and raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert rows[0] == exports.MESSAGE_HEADER and len(rows) == 3
    by_addr = {row[3]: row for row in rows[1:]}
    assert by_addr["a@gmail.com"][4] == "send" and by_addr["b@outlook.com"][4] == "bounce"
    assert by_addr["a@gmail.com"][1] == by_addr["b@outlook.com"][1]            # same message id on both rows
    assert by_addr["a@gmail.com"][7] == "webapp" and by_addr["a@gmail.com"][0].endswith("Z")


def test_export_follows_the_filters_on_the_page():
    mail(subject="keep me", app="billing", bounce="a@x.com")
    mail(subject="other app", app="webapp")
    mail(subject="billing but delivered", app="billing")
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    rows = read(c.get(reverse("messages_export") + "?app=billing&state=bounce"))
    assert [row[6] for row in rows[1:]] == ["keep me"]
    rows = read(c.get(reverse("messages_export") + "?q=other"))
    assert [row[6] for row in rows[1:]] == ["other app"]


def test_export_neutralises_hostile_subjects_and_recipients_and_survives_commas_and_newlines():
    mail(to=("+evil@x.com",), subject='=HYPERLINK("http://evil.example","click")')
    mail(to=("b@x.com",), subject='Has, a comma and\na newline and "quotes"')
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    rows = {row[6]: row for row in read(c.get(reverse("messages_export")))[1:]}
    assert "'=HYPERLINK(" in "".join(rows)                                   # the formula is text now
    assert not any(cell.startswith(("=", "+", "-", "@")) for row in rows.values() for cell in row)
    assert 'Has, a comma and\na newline and "quotes"' in rows                 # quoting round-trips through a CSV parser


def test_export_is_streamed_never_cached_and_named_safely():
    mail()
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    r = c.get(reverse("messages_export") + "?q=%22%0d%0aInjected:%20x")
    assert r.streaming and r["Cache-Control"] == "no-store"
    assert r["Content-Disposition"].startswith('attachment; filename="sent-mail-') and "\n" not in r["Content-Disposition"] and "Injected" not in r["Content-Disposition"]


def test_export_needs_the_capability_and_a_fresh_passkey():
    mail()
    for role in (VIEWER,):
        c, _ = login(role, f"{role}@example.com", step_up=True)
        assert c.get(reverse("messages_export")).status_code == 403
    c, _ = login(SUPPORT, "s@example.com")                                    # no passkey assertion yet
    r = c.get(reverse("messages_export") + "?app=webapp")
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up")) and "messages/export" in r["Location"]
    assert not AuditLog.objects.filter(action="export.messages").exists()      # nothing was exported, nothing is claimed
    from django.test import Client
    assert Client(HTTP_HOST="console.test").get(reverse("messages_export")).status_code == 302


def test_export_is_audited_with_counts_and_filters_but_no_addresses():
    mail(to=("secret.person@x.com",), app="billing")
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    read(c.get(reverse("messages_export") + "?app=billing&bogus=1"))
    row = AuditLog.objects.get(action="export.messages")
    assert row.actor == "s@example.com" and row.details == {"messages": 1, "filters": {"app": "billing"}}
    assert "secret.person" not in str(row.details)


def test_a_scoped_user_exports_only_their_own_domains():
    mail(to=("mine@x.com",), subject="mine", from_domain="example.com")
    mail(to=("theirs@x.com",), subject="not yours", from_domain="other-brand.com")
    c, _ = login(DELIVERABILITY_ADMIN, "scoped@example.com", step_up=True, scope_domains=["example.com"])
    rows = read(c.get(reverse("messages_export")))
    assert [row[6] for row in rows[1:]] == ["mine"] and "theirs@x.com" not in str(rows)


def test_export_refuses_to_start_above_the_row_cap(settings):
    settings.EXPORT_MAX_ROWS = 2
    for _ in range(3):
        mail()
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    r = c.get(reverse("messages_export") + "?app=webapp")
    assert r.status_code == 302 and r["Location"].startswith(reverse("messages")) and "app=webapp" in r["Location"]
    assert "Narrow the filters" in c.get(r["Location"]).content.decode()
    assert not AuditLog.objects.filter(action="export.messages").exists()


# ---------------------------------------------------------------- the suppression export
def sup(address, reason="BOUNCE", region="ap-south-1"):
    SuppressionEntry.objects.create(aws_account_id="1", region=region, address=address, address_lower=address.lower(), reason=reason,
                                    last_update_time=datetime.now(timezone.utc))


def test_suppression_export_rows_filter_region_and_audit():
    sup("Bob@X.com"), sup("amy@x.com", "COMPLAINT"), sup("zed@y.com"), sup("other@region.com", region="us-east-1")
    c, _ = login(SUPPORT, "s@example.com", step_up=True)
    rows = read(c.get(reverse("suppression_export")))
    assert rows[0] == exports.SUPPRESSION_HEADER
    assert [r[0] for r in rows[1:]] == ["amy@x.com", "Bob@X.com", "zed@y.com"] and rows[1][1] == "COMPLAINT"   # exact case kept
    assert [r[0] for r in read(c.get(reverse("suppression_export") + "?q=BO"))[1:]] == ["Bob@X.com"]
    assert AuditLog.objects.filter(action="export.suppression", actor="s@example.com").count() == 2


def test_suppression_export_needs_capability_and_passkey_and_respects_the_cap(settings):
    sup("a@x.com"), sup("b@x.com")
    assert login(VIEWER, "v@example.com", step_up=True)[0].get(reverse("suppression_export")).status_code == 403
    c, _ = login(SUPPORT, "s@example.com")
    assert c.get(reverse("suppression_export"))["Location"].startswith(reverse("step_up"))
    settings.EXPORT_MAX_ROWS = 1
    c2, _ = login(SUPPORT, "s2@example.com", step_up=True)
    assert c2.get(reverse("suppression_export")).status_code == 302


def test_export_row_cap_setting_is_validated_at_startup():
    for bad in ("0", "-5", "abc", "2000000", "1.5"):
        code, err = _import_settings(MC_EXPORT_MAX_ROWS=bad)
        assert code != 0 and "MC_EXPORT_MAX_ROWS" in err, bad
    assert _import_settings(MC_EXPORT_MAX_ROWS="250")[0] == 0


# ---------------------------------------------------------------- saved views
def test_canonical_params_keeps_only_known_keys_in_a_fixed_order_and_bounds_length():
    q = QueryDict("state=bounce&evil=1&page=3&open=9&app=billing&q=%20%20&days=7&sort=sent_at&dir=asc")
    assert exports.canonical_params(q) == "state=bounce&app=billing&days=7&sort=sent_at&dir=asc"
    assert exports.canonical_params(QueryDict("app=billing&state=bounce")) == exports.canonical_params(QueryDict("state=bounce&app=billing"))
    assert len(QueryDict(exports.canonical_params(QueryDict("q=" + "x" * 500)))["q"]) == exports.MAX_VALUE
    assert exports.canonical_params(QueryDict("")) == ""


def save(client, name="Billing bounces", params="app=billing&state=bounce", **extra):
    return client.post(reverse("saved_view_save"), {"name": name, "params": params, **extra})


def test_save_a_view_and_come_back_to_it():
    c, u = login(VIEWER, "v@example.com")
    r = save(c, params="state=bounce&app=billing&junk=<script>&page=4")
    assert r.status_code == 302 and r["Location"] == reverse("messages") + "?state=bounce&app=billing"
    v = SavedView.objects.get(user=u)
    assert v.name == "Billing bounces" and v.params == "state=bounce&app=billing"        # junk and page never stored
    html = c.get(reverse("messages")).content.decode()
    assert "Billing bounces" in html and "/messages/?state=bounce&amp;app=billing" in html


def test_saving_the_same_name_updates_it_and_names_are_per_person():
    c, u = login(VIEWER, "v@example.com")
    save(c, params="app=a")
    save(c, params="app=b")
    assert SavedView.objects.filter(user=u).count() == 1 and SavedView.objects.get(user=u).params == "app=b"
    c2, u2 = login(VIEWER, "w@example.com")
    save(c2, params="app=c")                                                              # same name, other person: separate view
    assert SavedView.objects.count() == 2 and SavedView.objects.get(user=u2).params == "app=c"


def test_save_validates_name_params_and_the_per_person_limit():
    c, u = login(VIEWER, "v@example.com")
    assert save(c, name="  ").status_code == 302 and not SavedView.objects.exists()
    assert save(c, params="").status_code == 302 and not SavedView.objects.exists()       # nothing to save
    assert save(c, params="evil=1&page=2").status_code == 302 and not SavedView.objects.exists()
    for i in range(exports.MAX_VIEWS_PER_USER):
        save(c, name=f"v{i}", params=f"q=x{i}")
    assert SavedView.objects.filter(user=u).count() == exports.MAX_VIEWS_PER_USER
    follow = save(c, name="one too many", params="q=zzz")
    assert SavedView.objects.filter(user=u).count() == exports.MAX_VIEWS_PER_USER
    assert "Delete one first" in c.get(follow["Location"]).content.decode()


def test_names_are_escaped_and_long_names_are_cut():
    c, u = login(VIEWER, "v@example.com")
    save(c, name="<script>alert(1)</script>" + "x" * 200, params="app=a")
    assert len(SavedView.objects.get(user=u).name) == 80
    html = c.get(reverse("messages")).content.decode()
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html


def test_you_can_delete_your_own_view_but_not_anyone_elses():
    mine_c, mine = login(VIEWER, "v@example.com")
    theirs_c, theirs = login(VIEWER, "w@example.com")
    save(mine_c, params="app=mine")
    save(theirs_c, params="app=theirs")
    their_view = SavedView.objects.get(user=theirs)
    assert mine_c.post(reverse("saved_view_delete", args=[their_view.pk])).status_code == 404   # not 403: do not confirm it exists
    assert SavedView.objects.filter(pk=their_view.pk).exists()
    mine_view = SavedView.objects.get(user=mine)
    assert mine_c.post(reverse("saved_view_delete", args=[mine_view.pk])).status_code == 302
    assert not SavedView.objects.filter(pk=mine_view.pk).exists()


def test_saved_views_are_private_to_their_owner_on_the_page():
    a, _ = login(VIEWER, "a@example.com")
    b, _ = login(VIEWER, "b@example.com")
    save(a, name="Only mine", params="app=x")
    assert "Only mine" in a.get(reverse("messages")).content.decode()
    assert "Only mine" not in b.get(reverse("messages")).content.decode()


def test_saved_view_endpoints_are_post_only_and_need_a_session():
    from django.test import Client
    c, _ = login(VIEWER, "v@example.com")
    assert c.get(reverse("saved_view_save")).status_code == 405 and c.get(reverse("saved_view_delete", args=[1])).status_code == 405
    anon = Client(HTTP_HOST="console.test")
    assert anon.post(reverse("saved_view_save"), {"name": "x", "params": "q=1"}).status_code == 302
    assert not SavedView.objects.exists()


def test_save_form_appears_only_when_there_is_something_to_save():
    c, _ = login(VIEWER, "v@example.com")
    assert "Save this view" not in c.get(reverse("messages")).content.decode()
    assert "Save this view" in c.get(reverse("messages") + "?state=bounce").content.decode()


# ---------------------------------------------------------------- the buttons
def test_export_buttons_show_only_to_people_who_may_export():
    mail()
    sup("a@x.com")
    support, _ = login(SUPPORT, "s@example.com")
    viewer, _ = login(VIEWER, "v@example.com")
    assert "Export CSV" in support.get(reverse("messages")).content.decode() and "Export CSV" in support.get(reverse("suppression")).content.decode()
    assert "Export CSV" not in viewer.get(reverse("messages")).content.decode() and "Export CSV" not in viewer.get(reverse("suppression")).content.decode()
    html = support.get(reverse("messages") + "?app=webapp&state=send").content.decode()
    assert "/messages/export/?state=send&amp;app=webapp" in html                              # the link carries the current filters
