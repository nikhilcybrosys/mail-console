import pytest
from django.urls import reverse

from apps.accounts import provisioning
from apps.accounts.models import User
from apps.audit.models import AuditLog
from apps.core.rbac import DELIVERABILITY_ADMIN, ROLES, SECURITY_ADMIN, SUPPORT, VIEWER
from apps.sesdata import setupcheck

from .test_views import login

pytestmark = pytest.mark.django_db


def add(client, email="new.person@example.com", role=VIEWER, name="", scope=""):
    return client.post(reverse("user_add"), {"email": email, "role": role, "name": name, "scope": scope})


@pytest.fixture
def boss():
    return login(SECURITY_ADMIN, "boss@example.com", step_up=True)


# ---------------------------------------------------------------- the checks
@pytest.mark.parametrize("text,good,bad", [
    ("example.com, Example.ORG ;mail.example.co.uk", ["example.com", "example.org", "mail.example.co.uk"], []),
    ("@example.com example.com", ["example.com"], []),
    ("", [], []),
    ("localhost, -bad.com, a..b.com, exa mple, https://x.com, example.c", [], ["localhost", "-bad.com", "a..b.com", "exa", "mple", "https://x.com", "example.c"]),
])
def test_scope_parsing(text, good, bad):
    got, rejected = provisioning.parse_scope(text)
    assert got == good and rejected == bad


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b@c.com", "a b@x.com", "a@x.com\r\nBcc: e@x.com", "müller@x.com", "a@", "@x.com", "x" * 250 + "@x.com"])
def test_bad_addresses_are_refused(email):
    data, errors = provisioning.check_new_user(email, VIEWER, "", "")
    assert errors and data["email"] == ""


def test_a_good_person_passes_and_is_normalised():
    data, errors = provisioning.check_new_user("  Ann.Lee@Example.COM ", SECURITY_ADMIN, "Ann\x00 Lee\r\n", "Example.com")
    assert errors == [] and data == {"email": "ann.lee@example.com", "role": SECURITY_ADMIN, "name": "Ann  Lee", "scope": ["example.com"]}


def test_sign_in_domain_is_enforced_because_anyone_else_could_not_sign_in(settings):
    settings.OIDC_ALLOWED_DOMAIN = "corp.example"
    assert any("limited to @corp.example" in e for e in provisioning.check_new_user("a@other.example", VIEWER, "", "")[1])
    assert provisioning.check_new_user("a@corp.example", VIEWER, "", "")[1] == []
    settings.OIDC_ALLOWED_DOMAIN = ""
    assert provisioning.check_new_user("a@other.example", VIEWER, "", "")[1] == []


def test_duplicates_are_refused_ignoring_case_and_the_role_must_exist():
    User.objects.create_user("dup@example.com", role=VIEWER)
    assert any("already has an account" in e for e in provisioning.check_new_user("DUP@example.com", VIEWER, "", "")[1])
    assert any("Choose a role" in e for e in provisioning.check_new_user("x@example.com", "root", "", "")[1])
    assert all(provisioning.check_new_user("x@example.com", r, "", "")[1] == [] for r in ROLES)


def test_an_account_stored_with_different_capitalisation_still_counts_as_a_duplicate():
    u = User.objects.create_user("mixed.case@example.com", role=VIEWER)
    User.objects.filter(pk=u.pk).update(email="Mixed.Case@Example.com")  # the manager lowercases; older or imported data need not be
    assert any("already has an account" in e for e in provisioning.check_new_user("mixed.case@example.com", VIEWER, "", "")[1])


def test_the_headcount_is_capped(monkeypatch):
    monkeypatch.setattr(provisioning, "MAX_USERS", 1)
    User.objects.create_user("one@example.com", role=VIEWER)
    assert any("At most" in e for e in provisioning.check_new_user("two@example.com", VIEWER, "", "")[1])


# ---------------------------------------------------------------- the page
def test_a_security_admin_adds_a_person_with_a_passkey_and_it_is_audited(boss):
    c, me = boss
    r = add(c, "ann@example.com", DELIVERABILITY_ADMIN, "Ann", "example.com")
    assert r.status_code == 302 and r["Location"] == reverse("users")
    u = User.objects.get(email="ann@example.com")
    assert (u.role, u.name, u.scope_domains, u.is_active, u.has_usable_password()) == (DELIVERABILITY_ADMIN, "Ann", ["example.com"], True, False)
    assert (u.oidc_issuer, u.oidc_subject) == ("", "")                     # bound on their first real sign-in, not now
    a = AuditLog.objects.get(action="user.created")
    assert a.actor == "boss@example.com" and a.target == "ann@example.com" and a.details == {"role": DELIVERABILITY_ADMIN, "scope": ["example.com"]}


def test_only_security_admins_may_add_people():
    for role in (VIEWER, SUPPORT, DELIVERABILITY_ADMIN):
        c, _ = login(role, f"{role}@example.com", step_up=True)
        assert add(c).status_code == 403, role
    assert User.objects.filter(email="new.person@example.com").count() == 0
    from django.test import Client
    assert add(Client(HTTP_HOST="console.test")).status_code == 302 and not User.objects.filter(email="new.person@example.com").exists()


def test_adding_needs_a_fresh_passkey_and_nothing_is_created_without_one():
    c, _ = login(SECURITY_ADMIN, "boss@example.com", step_up=False)
    r = add(c)
    assert r.status_code == 302 and r["Location"].startswith(reverse("step_up")) and not User.objects.filter(email="new.person@example.com").exists()
    assert not AuditLog.objects.filter(action="user.created").exists()


def test_errors_are_shown_with_the_values_kept_and_nothing_is_created(boss):
    c, _ = boss
    r = add(c, "not an email", "root", "<b>Ann</b>", "bad domain!")
    html = r.content.decode()
    assert r.status_code == 200 and "Enter a valid e-mail" in html and "Choose a role" in html and "Not a valid domain" in html
    assert "<b>Ann</b>" not in html and "&lt;b&gt;Ann&lt;/b&gt;" in html          # what they typed comes back escaped
    assert User.objects.count() == 1


def test_a_get_never_creates_anyone(boss):
    c, _ = boss
    r = c.get(reverse("user_add") + "?email=x@example.com&role=security_admin")
    assert r.status_code == 302 and User.objects.count() == 1


def test_the_new_person_appears_in_the_table_and_is_not_yet_signed_in(boss):
    c, _ = boss
    add(c, "ann@example.com", VIEWER)
    html = c.get(reverse("users")).content.decode()
    assert "ann@example.com" in html and "Never" in html and "Add a person" in html


def test_a_second_approver_clears_the_single_approver_warning(boss):
    c, _ = boss
    assert next(x for x in setupcheck.run_checks("ap-south-1") if x.key == "four").status == setupcheck.WARN
    add(c, "second@example.com", DELIVERABILITY_ADMIN)
    assert next(x for x in setupcheck.run_checks("ap-south-1") if x.key == "four").status == setupcheck.OK
