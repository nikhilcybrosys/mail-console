from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.compose import service
from apps.compose.models import Draft, SenderAddress, SentMail
from apps.core.rbac import DELIVERABILITY_ADMIN, SECURITY_ADMIN

from .test_compose import FROM, FakeSender, draft, go, me, on, ses  # noqa: F401  (fixtures and helpers)

pytestmark = pytest.mark.django_db
OTHER = "support@corp.example"


def limit(address, n):
    SenderAddress.objects.filter(address=address).update(daily_limit=n)


def sent(addr, n, hours_ago=1, by="x@example.com"):
    m = SentMail.objects.create(user_email=by, from_address=addr, subject="s", recipient_count=n, ses_message_id="m")
    SentMail.objects.filter(pk=m.pk).update(sent_at=timezone.now() - timedelta(hours=hours_ago))


def test_no_limit_means_unlimited_by_this_rule(on):
    assert service.address_left(FROM) is None and service.address_left("nobody@corp.example") is None


def test_the_limit_counts_everyones_sends_from_that_address_in_24_hours(on):
    limit(FROM, 10)
    sent(FROM, 3, by="a@example.com"), sent(FROM, 2, by="b@example.com")
    sent(FROM, 5, hours_ago=25)                                   # outside the window: does not count
    sent(OTHER, 9)                                                # another address: does not count
    assert service.address_left(FROM) == 5 and service.address_left(FROM.upper()) == 5
    sent(FROM, 20)
    assert service.address_left(FROM) == 0                        # never negative


def test_a_send_that_would_pass_the_address_limit_is_refused_and_nothing_is_sent(ses):
    limit(FROM, 3)
    _, u = me()
    sent(FROM, 2, by="someone.else@example.com")
    with pytest.raises(service.SendError, match="daily limit that would be passed \\(1 recipients left"):
        go(u, draft(u, to_text="a@x.com, b@x.com"))
    assert not ses.calls and Draft.objects.get().state == Draft.DRAFT
    go(u, draft(u, to_text="a@x.com"))                              # exactly the one left is fine
    assert len(ses.calls) == 1 and service.address_left(FROM) == 0


def test_the_address_limit_is_checked_for_the_address_used_not_for_others(ses):
    limit(FROM, 1)
    SenderAddress.objects.filter(address=OTHER).update(enabled=True)
    _, u = me()
    sent(FROM, 5)
    go(u, draft(u, from_address=OTHER, to_text="a@x.com"))        # OTHER has no limit of its own
    assert len(ses.calls) == 1


def test_the_address_limit_is_in_addition_to_the_person_limits(ses, on):
    limit(FROM, 100)
    on.SEND_PER_USER_PER_HOUR = 1
    on.SEND_PER_USER_PER_DAY, on.SEND_PER_DAY = 1, 1
    _, u = me()
    with pytest.raises(service.SendError, match="hourly limit"):
        go(u, draft(u, to_text="a@x.com, b@x.com"))


# ---------------------------------------------------------------- the settings page
def test_security_admin_sets_and_clears_a_limit_with_a_passkey_and_it_is_audited(on):
    c, _ = me(SECURITY_ADMIN, "s@example.com")
    r = c.post(reverse("compose_senders"), {"enabled_0": "on", "limit_0": "25"})
    assert r.status_code == 302 and SenderAddress.objects.get(address=FROM).daily_limit == 25
    a = AuditLog.objects.filter(action="compose.senders_updated").latest("id")
    assert a.details["changes"][FROM]["daily_limit"] == [None, 25]
    c.post(reverse("compose_senders"), {"enabled_0": "on", "limit_0": ""})
    assert SenderAddress.objects.get(address=FROM).daily_limit is None


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "1.5", "99999999", "301", " 12x"])
def test_bad_limits_are_rejected_and_nothing_is_saved(on, bad):
    c, _ = me(SECURITY_ADMIN, "s@example.com")
    r = c.post(reverse("compose_senders"), {"enabled_0": "on", "limit_0": bad})
    assert r.status_code == 200 and "daily limit must be a whole number" in r.content.decode()
    assert SenderAddress.objects.get(address=FROM).daily_limit is None and not AuditLog.objects.filter(action="compose.senders_updated").exists()


def test_the_limit_cannot_exceed_the_overall_daily_cap(on):
    c, _ = me(SECURITY_ADMIN, "s@example.com")
    assert c.post(reverse("compose_senders"), {"enabled_0": "on", "limit_0": str(on.SEND_PER_DAY)}).status_code == 302
    assert c.post(reverse("compose_senders"), {"enabled_0": "on", "limit_0": str(on.SEND_PER_DAY + 1)}).status_code == 200


def test_changing_the_limit_needs_a_passkey_and_only_security_admins_see_the_page(on):
    c, _ = me(SECURITY_ADMIN, "s@example.com", step_up=False)
    assert c.post(reverse("compose_senders"), {"limit_0": "5"})["Location"].startswith(reverse("step_up"))
    assert SenderAddress.objects.get(address=FROM).daily_limit is None
    d, _ = me(DELIVERABILITY_ADMIN, "d@example.com")
    assert d.post(reverse("compose_senders"), {"limit_0": "5"}).status_code == 403


def test_the_settings_page_shows_the_current_limit_and_the_preview_shows_what_is_left(on):
    limit(FROM, 40)
    sent(FROM, 15)
    c, u = me(SECURITY_ADMIN, "s@example.com")
    assert 'value="40"' in c.get(reverse("compose_senders")).content.decode()
    d = draft(u)
    page = c.get(reverse("compose_preview", args=[d.pk])).content.decode()
    assert "daily limit: 25 recipients left" in page
    limit(FROM, None)
    assert "daily limit:" not in c.get(reverse("compose_preview", args=[d.pk])).content.decode()
