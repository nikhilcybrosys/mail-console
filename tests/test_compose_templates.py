import pytest
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.compose import service
from apps.compose.models import Draft, MessageTemplate, SentMail
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN, SUPPORT, VIEWER

from .test_compose import FROM, FakeSender, draft, go, me, on, ses  # noqa: F401  (fixtures and helpers)

pytestmark = pytest.mark.django_db


def tpl(by="d@example.com", name="Welcome", subject="Hi {{first_name}}", body="Hello {{ first_name }},\n\nYour workspace {{workspace}} is ready.", from_address=FROM):
    return MessageTemplate.objects.create(name=name, name_lower=name.lower(), from_address=from_address, subject=subject, body=body, created_by=by, updated_by=by)


# ---------------------------------------------------------------- placeholders
def test_variables_are_found_in_order_without_duplicates():
    assert service.find_variables("Hi {{first_name}}", "{{ workspace }} and {{first_name}} and {{plan_2}}") == ["first_name", "workspace", "plan_2"]
    assert service.find_variables("no placeholders {single} {{ }} {{Upper}} {{1x}} {{a-b}}") == []


def test_anything_shaped_like_a_placeholder_is_reported_as_leftover():
    assert service.leftover_placeholders("{{first_name}} and {{ Weird Thing }} and {{}}") == ["{{first_name}}", "{{ Weird Thing }}", "{{}}"]
    assert service.leftover_placeholders("single {braces} are fine") == []


def test_filling_is_one_pass_so_a_value_cannot_pull_in_another_placeholder():
    out = service.fill("Hi {{a}} and {{b}}", {"a": "{{b}}", "b": "B"})
    assert out == "Hi {{b}} and B"                                  # the value is inserted as plain text, not expanded again
    assert service.check_values(["a"], {"a": "{{b}}"})              # and such a value is refused before it gets that far


@pytest.mark.parametrize("values,problem", [({}, "Fill in"), ({"a": ""}, "Fill in"), ({"a": "x" * 201}, "too long"), ({"a": "has }} braces"}, "double braces")])
def test_values_are_checked(values, problem):
    assert any(problem in e for e in service.check_values(["a"], values))


def test_values_lose_control_characters_so_a_subject_cannot_gain_a_line_break():
    assert service.clean_value("Ann\r\nBcc: evil@x.com\t") == "Ann  Bcc: evil@x.com"


# ---------------------------------------------------------------- the guard: an unfilled placeholder can never be sent
def test_a_draft_with_an_unfilled_placeholder_cannot_be_previewed_or_sent(ses):
    _, u = me()
    d = draft(u, subject="Hi {{first_name}}", body="Hello {{ first_name }}")
    p = service.prepare(d)
    assert not p.ok and "Fill in or remove" in p.errors[-1] and "{{first_name}}" in p.errors[-1]
    with pytest.raises(service.SendError, match="Fill in or remove"):
        service.send(u, d.pk, "anything", "ap-south-1")
    assert not ses.calls


def test_an_oddly_spelled_placeholder_is_also_stopped_rather_than_mailed(on):
    _, u = me()
    assert not service.prepare(draft(u, body="Hello {{ First Name }}")).ok


def test_filled_text_sends_normally_and_single_braces_are_fine(ses):
    _, u = me()
    sent = go(u, draft(u, subject="Hi Ann", body="Hello Ann, a {single} brace is fine"))
    assert sent.subject == "Hi Ann" and len(ses.calls) == 1


# ---------------------------------------------------------------- checking a template when it is saved
def test_template_checks(on):
    clean, errors = service.check_template("  Welcome   Mail ", FROM, "Hi {{first_name}}", "Body {{ plan }}")
    assert errors == [] and clean["name"] == "Welcome Mail"
    for args, needle in ((("", FROM, "s", "b"), "name"), (("n", "ceo@corp.example", "s", "b"), "default From"), (("n", FROM, "", "b"), "subject"),
                         (("n", FROM, "s" * 201, "b"), "too long"), (("n", FROM, "a\nb", "b"), "line breaks"), (("n", FROM, "s", ""), "Write the message"),
                         (("n", FROM, "s", "b" * 100_001), "too long"), (("n", FROM, "s", "Hi {{ Bad Name }}"), "Not valid"),
                         (("n", FROM, "s", " ".join("{{v%d}}" % i for i in range(21))), "At most 20")):
        assert any(needle in e for e in service.check_template(*args)[1]), args


def test_template_names_are_unique_ignoring_case(on):
    tpl(name="Welcome")
    assert any("already exists" in e for e in service.check_template("WELCOME", FROM, "s", "b")[1])
    t = MessageTemplate.objects.get()
    assert service.check_template("welcome", FROM, "s", "b", exclude_pk=t.pk)[1] == []      # renaming it to itself is fine


# ---------------------------------------------------------------- pages
def test_create_edit_and_delete_through_the_pages_with_audit_and_no_body_in_the_audit(on):
    c, u = me()
    r = c.post(reverse("compose_template_new"), {"name": "Welcome", "from_address": FROM, "subject": "Hi {{first_name}}", "body": "SECRET BODY {{first_name}}"})
    t = MessageTemplate.objects.get()
    assert r.status_code == 302 and (t.created_by, t.name_lower) == ("d@example.com", "welcome")
    a = AuditLog.objects.get(action="compose.template_created")
    assert a.details == {"name": "Welcome", "placeholders": ["first_name"]} and "SECRET" not in str(a.details)
    assert c.post(reverse("compose_template_edit", args=[t.pk]), {"name": "Welcome 2", "from_address": "", "subject": "New", "body": "Changed"}).status_code == 302
    t.refresh_from_db()
    assert (t.name, t.subject, t.from_address) == ("Welcome 2", "New", "") and AuditLog.objects.filter(action="compose.template_updated").exists()
    assert c.post(reverse("compose_template_delete", args=[t.pk])).status_code == 302 and not MessageTemplate.objects.exists()
    assert AuditLog.objects.filter(action="compose.template_deleted").exists()


def test_save_errors_are_shown_and_nothing_is_saved(on):
    c, _ = me()
    r = c.post(reverse("compose_template_new"), {"name": "", "subject": "Hi {{ Bad }}", "body": ""})
    assert r.status_code == 200 and "Fix these first" in r.content.decode() and not MessageTemplate.objects.exists()


def test_only_people_who_can_compose_can_use_the_library(on):
    t = tpl()
    for role in (VIEWER, SUPPORT):
        c, _ = me(role, f"{role}@example.com")
        for url in (reverse("compose_template_new"), reverse("compose_template_use", args=[t.pk]), reverse("compose_template_edit", args=[t.pk])):
            assert c.get(url).status_code == 403, (role, url)
        assert c.post(reverse("compose_template_delete", args=[t.pk])).status_code == 403
    assert MessageTemplate.objects.exists()


def test_others_templates_can_be_used_but_only_the_creator_or_a_security_admin_can_change_them(on):
    t = tpl(by="author@example.com")
    other, _ = me(DELIVERABILITY_ADMIN, "other@example.com")
    assert other.get(reverse("compose_template_use", args=[t.pk])).status_code == 200            # shared library: anyone who composes can use it
    assert other.get(reverse("compose_template_edit", args=[t.pk])).status_code == 404
    assert other.post(reverse("compose_template_edit", args=[t.pk]), {"name": "Hijack", "subject": "x", "body": "x"}).status_code == 404
    assert other.post(reverse("compose_template_delete", args=[t.pk])).status_code == 404
    t.refresh_from_db()
    assert t.name == "Welcome"
    boss, _ = me(SECURITY_ADMIN, "boss@example.com")
    assert boss.post(reverse("compose_template_delete", args=[t.pk])).status_code == 302 and not MessageTemplate.objects.exists()


def test_buttons_follow_permissions_on_the_home_page(on):
    t = tpl(by="author@example.com")
    other, _ = me(DELIVERABILITY_ADMIN, "other@example.com")
    html = other.get(reverse("compose")).content.decode()
    assert "Welcome" in html and reverse("compose_template_use", args=[t.pk]) in html
    edit, delete = f'href="{reverse("compose_template_edit", args=[t.pk])}"', f'action="{reverse("compose_template_delete", args=[t.pk])}"'
    assert edit not in html and delete not in html                                   # not theirs: no Edit, no Delete
    boss, _ = me(SECURITY_ADMIN, "boss@example.com")
    boss_html = boss.get(reverse("compose")).content.decode()
    assert edit in boss_html and delete in boss_html                                  # a security admin may change anyone's


def test_the_library_is_capped(on, monkeypatch):
    monkeypatch.setattr(service, "MAX_TEMPLATES", 2)
    tpl(name="a"), tpl(name="b")
    c, _ = me()
    c.post(reverse("compose_template_new"), {"name": "c", "subject": "s", "body": "b"})
    assert MessageTemplate.objects.count() == 2


# ---------------------------------------------------------------- using a template
def test_using_a_template_asks_for_each_placeholder_then_makes_an_ordinary_draft(ses):
    t = tpl()
    c, u = me()
    page = c.get(reverse("compose_template_use", args=[t.pk])).content.decode()
    assert 'name="var_first_name"' in page and 'name="var_workspace"' in page
    r = c.post(reverse("compose_template_use", args=[t.pk]), {"var_first_name": "Ann", "var_workspace": "Acme HQ"})
    d = Draft.objects.get()
    assert r["Location"] == reverse("compose_edit", args=[d.pk])
    assert (d.subject, d.from_address, d.to_text) == ("Hi Ann", FROM, "") and "Hello Ann," in d.body and "Acme HQ" in d.body and "{{" not in d.body
    assert d.state == Draft.DRAFT and not ses.calls and not SentMail.objects.exists()          # nothing was sent


def test_missing_or_hostile_values_are_refused_and_no_draft_is_made(on):
    t = tpl()
    c, _ = me()
    r = c.post(reverse("compose_template_use", args=[t.pk]), {"var_first_name": "", "var_workspace": "{{first_name}}"})
    html = r.content.decode()
    assert r.status_code == 200 and "Fill in first_name" in html and "double braces" in html and not Draft.objects.exists()


def test_values_cannot_inject_headers_or_markup_into_what_is_sent(ses):
    t = tpl(subject="Hi {{first_name}}", body="Hello {{first_name}}")
    c, u = me()
    c.post(reverse("compose_template_use", args=[t.pk]), {"var_first_name": 'Ann\r\nBcc: evil@x.com <script>alert(1)</script>'})
    d = Draft.objects.get()
    assert "\n" not in d.subject and "\r" not in d.subject
    d.to_text = "a@x.com"
    d.save()
    sent = go(u, d)
    call = ses.calls[0]
    assert call["bcc"] == [] and "<script>" not in call["html"] and "&lt;script&gt;" in call["html"] and sent.subject.startswith("Hi Ann")


def test_a_template_without_placeholders_still_needs_a_button_press_and_a_get_never_creates_anything(on):
    t = tpl(subject="Notice", body="Plain text")
    c, _ = me()
    r = c.get(reverse("compose_template_use", args=[t.pk]))
    assert r.status_code == 200 and "Create draft" in r.content.decode() and not Draft.objects.exists()   # shown, not done
    r = c.post(reverse("compose_template_use", args=[t.pk]))
    assert r.status_code == 302 and Draft.objects.get().body == "Plain text"


def test_following_a_template_link_never_changes_anything_even_with_placeholders(on):
    t = tpl()
    c, _ = me()
    for _ in range(3):
        c.get(reverse("compose_template_use", args=[t.pk]))
        c.get(reverse("compose_template_use", args=[t.pk]) + "?var_first_name=Ann&var_workspace=W")   # values in the URL are ignored
    assert not Draft.objects.exists()


def test_a_default_from_that_is_switched_off_is_left_blank_not_used(on):
    from apps.compose.models import SenderAddress
    SenderAddress.objects.filter(address=FROM).update(enabled=False)
    t = tpl()
    c, _ = me()
    c.post(reverse("compose_template_use", args=[t.pk]), {"var_first_name": "Ann", "var_workspace": "W"})
    assert Draft.objects.get().from_address == ""


def test_the_draft_count_cap_applies_when_using_templates(on):
    t = tpl(subject="s", body="b")
    c, u = me()
    for _ in range(service.MAX_DRAFTS_PER_USER):
        draft(u)
    c.post(reverse("compose_template_use", args=[t.pk]))
    assert Draft.objects.count() == service.MAX_DRAFTS_PER_USER


# ---------------------------------------------------------------- save as template
def test_a_draft_can_seed_a_template_but_only_your_own(on):
    c, u = me()
    mine = draft(u, subject="Mine", body="My text")
    other_user = me(email="o@example.com")[1]
    theirs = draft(other_user, subject="Theirs", body="Their private text")
    html = c.get(reverse("compose_template_new") + f"?from_draft={mine.pk}").content.decode()
    assert "My text" in html and 'value="Mine"' in html
    html2 = c.get(reverse("compose_template_new") + f"?from_draft={theirs.pk}").content.decode()
    assert "Their private text" not in html2 and "Theirs" not in html2
    assert "from_draft=%d" % mine.pk in c.get(reverse("compose_edit", args=[mine.pk])).content.decode()


def test_names_and_text_are_escaped_on_the_pages(on):
    tpl(name='<img src=x onerror=alert(1)>', subject="<b>s</b>", body="<script>alert(2)</script> {{x}}")
    c, _ = me()
    home = c.get(reverse("compose")).content.decode()
    use = c.get(reverse("compose_template_use", args=[MessageTemplate.objects.get().pk])).content.decode()
    for html in (home, use):
        assert "<img src=x" not in html and "<script>alert(2)" not in html and "<b>s</b>" not in html


def test_compose_templates_do_not_exist_when_compose_is_off(settings):
    settings.SEND_ENABLED = False
    c, _ = me()
    assert c.get(reverse("compose_template_new")).status_code == 404
