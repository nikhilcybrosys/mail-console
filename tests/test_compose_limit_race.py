import threading
import time

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from apps.compose import service
from apps.compose.models import Draft, SenderAddress, SentMail

from .test_compose import FROM, FakeSender, draft, go, me, on, ses  # noqa: F401  (fixtures and helpers)

OTHER = "support@corp.example"
# Transactional tests flush tables at the end with TRUNCATE, which the append-only audit log deliberately refuses. These tests only
# touch the apps below, so only their tables are flushed, and audit rows are not written here (that is covered elsewhere).
RACE = pytest.mark.django_db(transaction=True, available_apps=["apps.compose", "apps.accounts", "apps.sesdata"])


def person(email):
    from apps.accounts.models import User
    return User.objects.create_user(email, role="deliverability_admin")


@pytest.fixture
def no_audit(monkeypatch):
    monkeypatch.setattr(service, "record", lambda *a, **k: None)


def limit(address, n):
    SenderAddress.objects.filter(address=address).update(daily_limit=n)


# ---------------------------------------------------------------- reservations are counted
@pytest.mark.django_db
def test_sends_in_flight_or_unknown_count_against_every_limit_but_plain_drafts_do_not(on):
    _, u = me()
    limit(FROM, 10)
    draft(u, state=Draft.SENDING, reserved=3)
    draft(u, state=Draft.UNKNOWN, reserved=2)
    draft(u, state=Draft.DRAFT, reserved=9)                       # a plain draft reserves nothing, whatever the column says
    assert service.address_left(FROM) == 5
    use = service.usage(u.email)
    assert use["hour"] == use["day"] == use["all_day"] == 5
    other = me(email="o@example.com")[1]
    assert service.usage(other.email)["hour"] == 0 and service.usage(other.email)["all_day"] == 5   # per-person is per person, everyone's is shared


@pytest.mark.django_db
def test_a_reservation_blocks_a_second_send_that_would_not_fit(ses, on):
    _, a = me(email="a@example.com")
    _, b = me(email="b@example.com")
    limit(FROM, 2)
    draft(a, state=Draft.SENDING, reserved=2)                      # a's send is still in flight
    with pytest.raises(service.SendError, match="daily limit that would be passed"):
        go(b, draft(b, to_text="x@y.com"))
    assert not ses.calls


@pytest.mark.django_db
def test_the_reservation_is_taken_during_the_send_and_gone_after_success(monkeypatch, on):
    _, u = me()
    seen = {}

    class Spy(FakeSender):
        def send(self, **kw):
            seen["reserved"] = list(Draft.objects.values_list("state", "reserved"))
            return super().send(**kw)
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda *a: Spy())
    go(u, draft(u, to_text="a@x.com, b@x.com"))
    assert seen["reserved"] == [(Draft.SENDING, 2)]                # reserved while the call was in progress
    assert not Draft.objects.exists() and SentMail.objects.get().recipient_count == 2


@pytest.mark.django_db
def test_a_clean_refusal_releases_the_reservation_but_an_unknown_outcome_keeps_it(monkeypatch, on):
    _, u = me()
    err = ClientError({"Error": {"Code": "MessageRejected", "Message": "x"}}, "SendEmail")
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda *a: FakeSender(fail=err))
    d = draft(u, to_text="a@x.com, b@x.com")
    with pytest.raises(service.SendError):
        go(u, d)
    assert Draft.objects.get().reserved == 0 and Draft.objects.get().state == Draft.DRAFT      # not sent: nothing held back
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda *a: FakeSender(fail=ReadTimeoutError(endpoint_url="https://e.example")))
    with pytest.raises(service.SendError):
        go(u, Draft.objects.get())
    d = Draft.objects.get()
    assert (d.state, d.reserved) == (Draft.UNKNOWN, 2) and service.usage(u.email)["day"] == 2   # it may have gone out: stays counted


@pytest.mark.django_db
def test_releasing_an_unknown_draft_gives_the_reservation_back(on):
    c, u = me()
    d = draft(u, state=Draft.UNKNOWN, reserved=4)
    from django.urls import reverse
    c.post(reverse("compose_release", args=[d.pk]))
    d.refresh_from_db()
    assert (d.state, d.reserved) == (Draft.DRAFT, 0) and service.usage(u.email)["day"] == 0


# ---------------------------------------------------------------- the race itself, against real PostgreSQL
def run_two_sends(monkeypatch, make_users):
    """Two people send at the same moment. The check is slowed down so that, without serialisation, both would see the
    same free capacity before either had reserved anything."""
    real = service.check_limits

    def slow_check(*a, **k):
        real(*a, **k)
        time.sleep(0.4)                                            # the window in which the race used to live
    monkeypatch.setattr(service, "check_limits", slow_check)
    monkeypatch.setattr("apps.sesdata.aws.assume_sender", lambda *a: FakeSender())
    (ua, da), (ub, db) = make_users()
    barrier, results = threading.Barrier(2), {}

    def worker(name, user, d):
        from django.db import connection
        try:
            p = service.prepare(d, "ap-south-1")
            barrier.wait()
            service.send(user, d.pk, service.content_hash(p), "ap-south-1")
            results[name] = "sent"
        except service.SendError as exc:
            results[name] = "refused"
        except Exception as exc:  # noqa: BLE001
            results[name] = f"error {exc.__class__.__name__}"
        finally:
            connection.close()
    threads = [threading.Thread(target=worker, args=("a", ua, da)), threading.Thread(target=worker, args=("b", ub, db))]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    return results


@RACE
def test_two_simultaneous_sends_cannot_both_fit_under_an_address_limit_of_one(monkeypatch, on, no_audit):
    a = person("a@example.com")
    b = person("b@example.com")
    limit(FROM, 1)
    res = run_two_sends(monkeypatch, lambda: ((a, draft(a, to_text="x@y.com")), (b, draft(b, to_text="z@y.com"))))
    assert sorted(res.values()) == ["refused", "sent"], res
    assert SentMail.objects.count() == 1 and service.address_left(FROM) == 0


@RACE
def test_the_same_holds_for_the_everyone_limit_across_different_addresses(monkeypatch, on, no_audit):
    on.SEND_PER_DAY = 1
    SenderAddress.objects.filter(address=OTHER).update(enabled=True)
    a = person("a@example.com")
    b = person("b@example.com")
    res = run_two_sends(monkeypatch, lambda: ((a, draft(a, to_text="x@y.com")), (b, draft(b, from_address=OTHER, to_text="z@y.com"))))
    assert sorted(res.values()) == ["refused", "sent"], res


@RACE
def test_the_same_holds_for_one_persons_hourly_limit_with_two_drafts(monkeypatch, on, no_audit):
    on.SEND_PER_USER_PER_HOUR, on.SEND_PER_USER_PER_DAY, on.SEND_PER_DAY = 1, 1, 5
    a = person("a@example.com")
    res = run_two_sends(monkeypatch, lambda: ((a, draft(a, to_text="x@y.com")), (a, draft(a, to_text="z@y.com"))))
    assert sorted(res.values()) == ["refused", "sent"], res


@RACE
def test_when_there_is_room_for_both_both_are_sent(monkeypatch, on, no_audit):
    a = person("a@example.com")
    b = person("b@example.com")
    limit(FROM, 5)
    res = run_two_sends(monkeypatch, lambda: ((a, draft(a, to_text="x@y.com")), (b, draft(b, to_text="z@y.com"))))
    assert res == {"a": "sent", "b": "sent"} and SentMail.objects.count() == 2
