"""Copying archived mail into a Google Workspace mailbox: the Google client, the scan, idempotence, failures, the checks and the settings."""
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.sesdata import alerts, archive, archive_sync, gmail, setupcheck
from apps.sesdata.models import Alert, ArchiveSyncItem, ArchiveSyncState

pytestmark = pytest.mark.django_db
ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
MAILBOX = "info@corp.example"


# ---------------------------------------------------------------- a stand-in for Google
class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body if body is not None else {}

    def json(self):
        return self._body


class FakeGoogle:
    """Answers the token endpoint and the Gmail API. `script` lets a test make specific calls fail."""

    def __init__(self):
        self.calls, self.labels, self.script, self.n = [], {"INBOX": "INBOX", "SENT": "SENT"}, [], 0

    def post(self, url, data=None, timeout=None):
        self.calls.append(("token", url, data))
        return self.script.pop(0) if self.script and self.script[0] == "token-fail" and not self.script.pop(0) else Resp(200, {"access_token": f"tok{len(self.calls)}", "expires_in": 3600})

    def request(self, method, url, headers=None, timeout=None, json=None, **kw):
        path = url.replace(gmail.API, "")
        self.calls.append((method, path, headers, json))
        if self.script:
            nxt = self.script.pop(0)
            if isinstance(nxt, Resp) or isinstance(nxt, Exception):
                if isinstance(nxt, Exception):
                    raise nxt
                return nxt
        if method == "GET" and path == "/labels":
            return Resp(200, {"labels": [{"id": v, "name": k} for k, v in self.labels.items()]})
        if method == "POST" and path == "/labels":
            self.n += 1
            self.labels[json["name"]] = f"Label_{self.n}"
            return Resp(200, {"id": f"Label_{self.n}", "name": json["name"]})
        if method == "POST" and path.startswith("/messages"):
            self.n += 1
            return Resp(200, {"id": f"gm{self.n}"})
        raise AssertionError((method, path))


def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return key, {"client_email": "sync@proj.iam.example", "private_key": pem}


def sa_auth(session=None, clock=lambda: 1_000_000.0):
    key, sa = keypair()
    g = session or FakeGoogle()
    return gmail.Auth(MAILBOX, service_account=sa, session=g, clock=clock), g, key


# ---------------------------------------------------------------- authentication
def test_the_service_account_assertion_is_a_correctly_signed_jwt_for_exactly_one_mailbox_and_two_scopes():
    auth, g, key = sa_auth()
    assert auth.token() == "tok1"
    (kind, url, data) = g.calls[0]
    assert url == gmail.TOKEN_URL and data["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    head, claims, sig = data["assertion"].split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    body = json.loads(base64.urlsafe_b64decode(pad(claims)))
    assert json.loads(base64.urlsafe_b64decode(pad(head))) == {"alg": "RS256", "typ": "JWT"}
    assert body["iss"] == "sync@proj.iam.example" and body["sub"] == MAILBOX and body["aud"] == gmail.TOKEN_URL and body["exp"] - body["iat"] == 3600
    assert set(body["scope"].split()) == {"https://www.googleapis.com/auth/gmail.insert", "https://www.googleapis.com/auth/gmail.labels"}
    key.public_key().verify(base64.urlsafe_b64decode(pad(sig)), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())   # raises if the signature is wrong


def test_a_key_file_cannot_redirect_where_credentials_are_sent():
    key, sa = keypair()
    sa["token_uri"] = "https://evil.example/token"
    g = FakeGoogle()
    gmail.Auth(MAILBOX, service_account=sa, session=g).token()
    assert g.calls[0][1] == gmail.TOKEN_URL
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    claims = json.loads(base64.urlsafe_b64decode(pad(g.calls[0][2]["assertion"].split(".")[1])))
    assert claims["aud"] == gmail.TOKEN_URL         # the signed token names Google's endpoint too, not whatever the key file says


def test_the_token_is_cached_and_renewed_a_minute_before_it_expires():
    now = [1_000_000.0]
    auth, g, _ = sa_auth(clock=lambda: now[0])
    assert auth.token() == auth.token() and len(g.calls) == 1
    now[0] += 3600 - 61
    auth.token()
    assert len(g.calls) == 1
    now[0] += 2
    assert auth.token() == "tok2" and len(g.calls) == 2


def test_the_oauth_refresh_token_flow_sends_the_three_values_and_nothing_else():
    g = FakeGoogle()
    gmail.Auth(MAILBOX, oauth={"client_id": "cid", "client_secret": "sec", "refresh_token": "rt"}, session=g).token()
    assert g.calls[0][2] == {"grant_type": "refresh_token", "client_id": "cid", "client_secret": "sec", "refresh_token": "rt"}


@pytest.mark.parametrize("kw", [{}, {"service_account": {"a": 1}, "oauth": {"b": 2}}])
def test_exactly_one_kind_of_credential_is_required(kw):
    with pytest.raises(gmail.GoogleError):
        gmail.Auth(MAILBOX, session=FakeGoogle(), **kw)


def test_a_malformed_private_key_is_reported_plainly():
    auth = gmail.Auth(MAILBOX, service_account={"client_email": "x@y", "private_key": "not a key"}, session=FakeGoogle())
    with pytest.raises(gmail.GoogleError, match="not a valid private key"):
        auth.token()


def test_a_missing_or_broken_key_file_is_reported_plainly_without_the_path_or_contents(tmp_path, settings):
    settings.GOOGLE_SERVICE_ACCOUNT_FILE, settings.ARCHIVE_SYNC_MAILBOX = str(tmp_path / "nope.json"), MAILBOX
    with pytest.raises(gmail.GoogleError) as e:
        gmail.Auth.from_settings(settings)
    assert str(tmp_path) not in str(e.value)
    bad = tmp_path / "bad.json"
    bad.write_text('{"client_email": "x"}')
    settings.GOOGLE_SERVICE_ACCOUNT_FILE = str(bad)
    with pytest.raises(gmail.GoogleError):
        gmail.Auth.from_settings(settings)


def test_a_refused_token_request_never_passes_on_googles_text(monkeypatch):
    g = FakeGoogle()
    g.post = lambda url, data=None, timeout=None: Resp(400, {"error": "invalid_grant", "error_description": "secret detail from Google"})
    auth = gmail.Auth(MAILBOX, oauth={"client_id": "c", "client_secret": "s", "refresh_token": "r"}, session=g)
    with pytest.raises(gmail.GoogleError) as e:
        auth.token()
    assert "refused the credentials" in str(e.value) and "secret detail" not in str(e.value) and "invalid_grant" not in str(e.value)


def test_a_network_failure_getting_a_token_is_reported_plainly():
    g = FakeGoogle()

    def boom(*a, **k):
        raise requests.ConnectionError("dns secret")
    g.post = boom
    with pytest.raises(gmail.GoogleError) as e:
        gmail.Auth(MAILBOX, oauth={"client_id": "c", "client_secret": "s", "refresh_token": "r"}, session=g).token()
    assert "could not be reached" in str(e.value) and "secret" not in str(e.value)


# ---------------------------------------------------------------- the Gmail calls
def mail(session=None, **kw):
    auth, g, _ = sa_auth(session)
    return gmail.Gmail(auth, g, sleep=lambda s: None), g


def test_a_label_is_found_case_insensitively_and_created_once_if_missing():
    gm, g = mail()
    g.labels["Sent via SES"] = "L1"
    assert gm.label("sent VIA ses") == "L1"
    new = gm.label("Sent via SES/Cloud")
    assert new == gm.label("sent via ses/cloud") and [c for c in g.calls if c[0] == "POST"].__len__() == 1


def test_a_label_created_in_the_meantime_is_found_after_a_conflict():
    gm, g = mail()
    gm.labels()
    g.script = [Resp(409, {})]
    g.labels["Race"] = "L9"
    assert gm.label("Race") == "L9"


def test_inserting_sends_the_exact_original_bytes_with_exactly_the_given_labels_and_the_original_date():
    gm, g = mail()
    raw = b"From: a@b.example\r\nSubject: =?utf-8?q?caf=C3=A9?=\r\n\r\nbody \xff\xfe bytes\r\n"
    assert gm.insert(raw, ["Label_1", "Label_2"]) == "gm1"
    method, path, headers, body = g.calls[-1]
    assert (method, path) == ("POST", "/messages?internalDateSource=dateHeader") and headers["Authorization"].startswith("Bearer tok")
    assert base64.urlsafe_b64decode(body["raw"] + "=" * (-len(body["raw"]) % 4)) == raw and body["labelIds"] == ["Label_1", "Label_2"] and set(body) == {"raw", "labelIds"}


def test_an_expired_token_is_renewed_once_and_the_call_repeated():
    gm, g = mail()
    g.script = [Resp(401, {})]
    assert gm.insert(b"x", ["L"]) == "gm1"
    assert [c[0] for c in g.calls].count("token") == 2


def test_throttling_and_server_errors_are_retried_and_a_persistent_failure_is_reported_plainly():
    sleeps = []
    auth, g, _ = sa_auth()
    gm = gmail.Gmail(auth, g, sleep=sleeps.append)
    g.script = [Resp(429, {}), Resp(503, {}), requests.Timeout("t")]
    assert gm.insert(b"x", ["L"]) == "gm1" and sleeps == [1, 2, 4]
    g.script = [Resp(500, {})] * 10
    with pytest.raises(gmail.GoogleError, match="did not answer"):
        gm.insert(b"x", ["L"])


@pytest.mark.parametrize("status", [400, 403, 404])
def test_a_refusal_is_reported_without_googles_text_and_with_a_hint_for_permission_errors(status):
    gm, g = mail()
    g.script = [Resp(status, {"error": {"message": "secret detail from Google"}})]
    with pytest.raises(gmail.GoogleError) as e:
        gm.insert(b"x", ["L"])
    assert "secret detail" not in str(e.value) and (status != 403 or "not authorised" in str(e.value))


def test_the_credential_check_counts_labels_and_fails_plainly_when_the_mailbox_is_not_authorised():
    gm, g = mail()
    assert gm.check() == 2
    g.script = [Resp(403, {})]
    with pytest.raises(gmail.GoogleError, match="not authorised"):
        gm.check()


# ---------------------------------------------------------------- the scan
def row(i, t, frm="Acme <cloud@corp.example>"):
    from email.utils import parseaddr
    return {"ArchivedMessageId": f"0c/a-1/id{i}/id{i}", "MessageId": f"<id{i}@ap-south-1.amazonses.com>", "From": frm, "To": "x@y.example", "Subject": "s", "t": t,
            "Envelope": {"From": parseaddr(frm)[1], "To": ["x@y.example"]}}


class FakeMM:
    """An archive with messages at given times: answers searches for a window, at most MaxResults at a time."""

    def __init__(self, rows=(), created=NOW - timedelta(days=2)):
        self.rows, self.created, self.searches, self.dl = list(rows), created, [], []

    def get_archive(self, ArchiveId):
        return {"ArchiveState": "ACTIVE", "CreatedTimestamp": self.created}

    def start_archive_search(self, **kw):
        self.searches.append((kw["FromTimestamp"], kw["ToTimestamp"]))
        hits = [r for r in self.rows if kw["FromTimestamp"] <= r["t"] <= kw["ToTimestamp"]]
        for cond in (kw.get("Filters") or {}).get("Include", []):
            expr = cond["StringExpression"]
            assert expr["Operator"] == "CONTAINS"
            if expr["Evaluate"]["Attribute"] == "ENVELOPE_FROM":
                hits = [r for r in hits if expr["Values"][0] in r["Envelope"]["From"]]
            else:
                assert expr["Evaluate"]["Attribute"] == "ENVELOPE_TO"
                hits = [r for r in hits if any(expr["Values"][0] in t for t in r["Envelope"]["To"])]
        hits = hits[:kw["MaxResults"]]
        FakeMM.last_filters = kw.get("Filters")
        self._hits = [{k: v for k, v in r.items() if k != "t"} for r in hits]
        return {"SearchId": "s"}

    def get_archive_search(self, SearchId):
        return {"Status": {"State": "COMPLETED"}}

    def get_archive_search_results(self, SearchId):
        return {"Rows": self._hits}

    def get_archive_message(self, ArchivedMessageId):
        self.dl.append(ArchivedMessageId)
        return {"MessageDownloadLink": "https://dl.example/" + ArchivedMessageId}


class FakeGmail:
    def __init__(self, fail=None):
        self.inserted, self.fail, self.created = [], fail or {}, {}

    def label(self, name):
        return self.created.setdefault(name, f"L:{name}")

    def insert(self, raw, labels):
        key = raw.decode(errors="replace")
        if self.fail.get(key):
            raise self.fail[key]
        self.inserted.append((raw, labels))
        return f"g{len(self.inserted)}"


def sync(mm, gm, raws=None, **kw):
    s = archive_sync.Sync(reader=archive.Reader(mm=mm, archive_id="a-1", sleep=lambda s: None), gmail=gm,
                         fetch=lambda url: (raws or {}).get(url.rsplit("/", 1)[1], url.rsplit("/", 1)[1].encode()))
    return s


@pytest.fixture(autouse=True)
def cfg(settings):
    settings.ARCHIVE_SYNC_LABEL_ROOT, settings.ARCHIVE_SYNC_MAILBOX, settings.ARCHIVE_SYNC_INTERVAL, settings.ARCHIVE_SYNC_ENABLED = "Sent via SES", MAILBOX, 300, True


@pytest.mark.parametrize("header, expected", [
    ("Acme <cloud@corp.example>", "Cloud"), ("ops-watchdog@corp.example", "Ops-Watchdog"), ("No Reply <no-reply@corp.example>", "No-Reply"),
    ("NOTIFICATIONS@corp.example", "Notifications"), ("a.b_c@corp.example", "A-B-C"), ("", "Other"), ("garbage", "Garbage"), ("<>", "Other"),
    ("x" * 200 + "@corp.example", "X" + "x" * 59),
])
def test_the_label_is_the_senders_name_made_safe(header, expected):
    assert archive_sync.label_name(header) == expected


def test_the_first_pass_starts_at_the_archives_creation_and_copies_every_message_under_two_labels():
    mm = FakeMM([row(1, NOW - timedelta(hours=30)), row(2, NOW - timedelta(minutes=10), "Pay <payments@corp.example>")], created=NOW - timedelta(days=2))
    gm = FakeGmail()
    stats = sync(mm, gm).run_once(NOW)
    assert (stats["imported"], stats["failed"]) == (2, 0)
    assert mm.searches[0][0] <= NOW - timedelta(days=2, minutes=1)
    assert [labels for _, labels in gm.inserted] == [["L:Sent via SES", "L:Sent via SES/Cloud"], ["L:Sent via SES", "L:Sent via SES/Payments"]]
    st = ArchiveSyncState.objects.get()
    assert st.scanned_to == NOW - archive_sync.LAG and st.last_ok_at == NOW
    assert set(ArchiveSyncItem.objects.values_list("state", flat=True)) == {"imported"}


def test_only_the_given_labels_are_ever_used_never_the_inbox_unread_or_sent():
    mm, gm = FakeMM([row(1, NOW - timedelta(hours=1))]), FakeGmail()
    sync(mm, gm).run_once(NOW)
    ((_, labels),) = gm.inserted
    assert not {"INBOX", "UNREAD", "SENT", "SPAM", "TRASH"} & set(labels) and len(labels) == 2


def test_the_original_bytes_are_inserted_unchanged():
    raw = b"From: a@b\r\n\r\n\xff\x00\xfe original"
    mm, gm = FakeMM([row(1, NOW - timedelta(hours=1))]), FakeGmail()
    sync(mm, gm, {"id1": raw}).run_once(NOW)
    assert gm.inserted[0][0] == raw


def test_a_second_pass_imports_nothing_again_even_though_the_last_hour_is_scanned_again():
    mm, gm = FakeMM([row(1, NOW - timedelta(minutes=30))]), FakeGmail()
    s = sync(mm, gm)
    s.run_once(NOW)
    s2 = sync(mm, gm)
    s2.run_once(NOW + timedelta(minutes=5))
    assert len(gm.inserted) == 1 and s2.stats["imported"] == 0 and ArchiveSyncItem.objects.count() == 1


def test_the_next_pass_resumes_from_the_scan_point_minus_the_overlap():
    mm, gm = FakeMM([]), FakeGmail()
    sync(mm, gm).run_once(NOW)
    mm.searches.clear()
    sync(mm, gm).run_once(NOW + timedelta(minutes=5))
    assert mm.searches[0][0] == NOW - archive_sync.LAG - archive_sync.RESCAN - timedelta(seconds=1)


def test_a_message_that_reaches_the_archive_late_is_still_picked_up_within_the_last_hour():
    mm, gm = FakeMM([]), FakeGmail()
    sync(mm, gm).run_once(NOW)
    mm.rows.append(row(7, NOW - timedelta(minutes=30)))          # archived after the scan had passed its time
    s = sync(mm, gm)
    s.run_once(NOW + timedelta(minutes=5))
    assert s.stats["imported"] == 1


def test_a_full_window_is_split_so_no_message_is_cut_off_and_none_is_imported_twice():
    rows = [row(i, NOW - timedelta(hours=5) + timedelta(seconds=i * 10)) for i in range(120)]
    mm, gm = FakeMM(rows, created=NOW - timedelta(hours=6)), FakeGmail()
    s = sync(mm, gm)
    s.run_once(NOW)
    assert s.stats["imported"] == 120 and ArchiveSyncItem.objects.count() == 120 and len({r for r, _ in gm.inserted}) == 120 and s.stats["windows"] > 3


def test_a_moment_with_too_many_messages_is_told_apart_by_sender_and_nothing_is_lost():
    t = NOW - timedelta(hours=1)
    rows = [row(i, t, f"A <s{i % 3}@corp.example>") for i in range(60)]          # 60 at one instant, 20 from each of three senders
    mm, gm = FakeMM(rows, created=NOW - timedelta(hours=2)), FakeGmail()
    s = sync(mm, gm)
    s.run_once(NOW)
    assert s.stats["imported"] == 60 and s.incomplete == [] and ArchiveSyncState.objects.get().last_ok_at == NOW and ArchiveSyncState.objects.get().incomplete_at is None


def test_a_moment_that_one_sender_alone_fills_is_flagged_incomplete_and_never_called_a_clean_pass():
    """The review finding: the scan used to move on from such a window and report success, silently dropping messages."""
    t = NOW - timedelta(hours=1)
    mm, gm = FakeMM([row(i, t) for i in range(60)], created=NOW - timedelta(hours=2)), FakeGmail()
    s = sync(mm, gm)
    s.run_once(NOW)
    st = ArchiveSyncState.objects.get()
    assert s.stats["imported"] == 50 and len(s.incomplete) == 1
    assert st.last_ok_at is None and st.incomplete_at == NOW and st.incomplete_windows == 1 and st.scanned_to == NOW - archive_sync.LAG   # it moves on (it must not be stuck), but says so


def test_an_incomplete_window_shows_in_the_setup_check_and_opens_an_alert_for_two_weeks_only():
    ArchiveSyncState.objects.create(pk=1, last_ok_at=NOW, incomplete_at=NOW - timedelta(days=3), incomplete_windows=2)
    c = by_key(setupcheck._archive_sync_checks(NOW, OkGmail()))
    assert c["minc"].status == "fail" and "2 such moment" in c["minc"].detail
    assert "minc" not in by_key(setupcheck._archive_sync_checks(NOW + timedelta(days=20), OkGmail()))        # shown for two weeks only


def test_the_incomplete_alert_opens_and_resolves():
    now = datetime.now(timezone.utc)
    ArchiveSyncState.objects.create(pk=1, last_ok_at=now, incomplete_at=now - timedelta(days=1), incomplete_windows=1)
    alerts.evaluate()
    assert Alert.objects.filter(key="archive_sync_incomplete", resolved_at__isnull=True).count() == 1
    ArchiveSyncState.objects.update(incomplete_at=now - timedelta(days=20))
    alerts.evaluate()
    assert not Alert.objects.filter(key="archive_sync_incomplete", resolved_at__isnull=True).exists()


def test_the_sender_filter_is_sent_to_the_archive_search_exactly(settings):
    mm = FakeMM([row(1, NOW)])
    r = archive.Reader(mm=mm, archive_id="a-1", sleep=lambda s: None)
    expr = lambda attr, value: {"StringExpression": {"Evaluate": {"Attribute": attr}, "Operator": "CONTAINS", "Values": [value]}}  # noqa: E731
    r._search(NOW - timedelta(minutes=1), NOW + timedelta(minutes=1), sender="cloud@corp.example")
    assert FakeMM.last_filters == {"Include": [expr("ENVELOPE_FROM", "cloud@corp.example")]}
    r._search(NOW - timedelta(minutes=1), NOW + timedelta(minutes=1), recipient="bob@y.example")
    assert FakeMM.last_filters == {"Include": [expr("ENVELOPE_TO", "bob@y.example")]}
    r._search(NOW - timedelta(minutes=1), NOW + timedelta(minutes=1))
    assert FakeMM.last_filters is None


def test_a_failure_is_recorded_without_stopping_the_others_and_the_scan_is_not_called_clean():
    mm = FakeMM([row(1, NOW - timedelta(hours=3)), row(2, NOW - timedelta(hours=2)), row(3, NOW - timedelta(hours=1))])
    gm = FakeGmail(fail={"id2": gmail.GoogleError("Google did not answer (it kept refusing or timing out). It will be tried again.")})
    s = sync(mm, gm)
    s.run_once(NOW)
    assert (s.stats["imported"], s.stats["failed"]) == (2, 1)
    bad = ArchiveSyncItem.objects.get(state="failed")
    assert bad.attempts == 1 and "did not answer" in bad.detail and ArchiveSyncState.objects.get().last_ok_at is None


def test_a_failed_message_is_retried_on_the_next_pass_and_then_succeeds():
    mm = FakeMM([row(1, NOW - timedelta(hours=1))])
    gm = FakeGmail(fail={"id1": gmail.GoogleError("later")})
    sync(mm, gm).run_once(NOW)
    gm.fail.clear()
    s = sync(mm, gm)
    s.run_once(NOW + timedelta(minutes=5))
    item = ArchiveSyncItem.objects.get()
    assert item.state == "imported" and item.attempts == 2 and item.gmail_id and ArchiveSyncState.objects.get().last_ok_at == NOW + timedelta(minutes=5)


def test_retrying_gives_up_after_the_maximum_attempts_and_records_that():
    mm, gm = FakeMM([row(1, NOW - timedelta(hours=1))]), FakeGmail(fail={"id1": gmail.GoogleError("nope")})
    for i in range(archive_sync.MAX_ATTEMPTS + 3):
        sync(mm, gm).run_once(NOW + timedelta(minutes=5 * i))
    item = ArchiveSyncItem.objects.get()
    assert item.state == "failed" and item.attempts == archive_sync.MAX_ATTEMPTS


def test_an_unexpected_error_records_only_its_class_never_its_text():
    mm = FakeMM([row(1, NOW - timedelta(hours=1))])
    gm = FakeGmail(fail={"id1": RuntimeError("secret detail from somewhere")})
    sync(mm, gm).run_once(NOW)
    assert ArchiveSyncItem.objects.get().detail == "RuntimeError"


def test_a_message_over_the_size_limit_is_skipped_recorded_and_not_retried():
    mm, gm = FakeMM([row(1, NOW - timedelta(hours=1))]), FakeGmail()
    big = b"x" * (archive_sync.MAX_RAW + 1)
    sync(mm, gm, {"id1": big}).run_once(NOW)
    sync(mm, gm, {"id1": big}).run_once(NOW + timedelta(minutes=5))
    item = ArchiveSyncItem.objects.get()
    assert item.state == "skipped" and "10 MB" in item.detail and gm.inserted == [] and item.attempts == 1


def test_no_message_content_is_ever_stored_in_the_database():
    mm, gm = FakeMM([row(1, NOW - timedelta(hours=1))]), FakeGmail()
    sync(mm, gm, {"id1": b"TOP SECRET BODY"}).run_once(NOW)
    stored = json.dumps(list(ArchiveSyncItem.objects.values()), default=str) + json.dumps(list(ArchiveSyncState.objects.values()), default=str)
    assert "TOP SECRET" not in stored


# ---------------------------------------------------------------- the download
class DL:
    def __init__(self, chunks, status=200):
        self.chunks, self.status_code, self.read = chunks, status, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, n):
        for c in self.chunks:
            self.read += len(c)
            yield c


def test_only_https_links_are_followed_and_a_bad_status_is_an_error():
    for url in ("http://x.example/m", "file:///etc/passwd", "ftp://x/m", "//x/m"):
        with pytest.raises(archive.ArchiveError):
            archive_sync.download(url, get=lambda *a, **k: DL([b"x"]))
    with pytest.raises(archive.ArchiveError):
        archive_sync.download("https://x.example/m", get=lambda *a, **k: DL([b"x"], 403))


def test_a_huge_download_is_cut_off_instead_of_read_to_the_end():
    d = DL([b"x" * 1_000_000] * 100)
    data = archive_sync.download("https://x.example/m", get=lambda *a, **k: d)
    assert archive_sync.MAX_RAW < len(data) <= archive_sync.MAX_RAW + 1_000_000 and d.read < 20_000_000


# ---------------------------------------------------------------- the worker, checks and alerts
def test_the_worker_refuses_to_start_when_the_copy_is_off(settings):
    settings.ARCHIVE_SYNC_ENABLED = False
    with pytest.raises(CommandError, match="mailbox copy is off"):
        call_command("sync_archive_to_mailbox", "--once")


def test_the_worker_runs_one_pass_and_touches_its_heartbeat_and_a_failing_pass_does_not_crash_it(settings, tmp_path, monkeypatch):
    settings.WORKER_HEARTBEAT_FILE = str(tmp_path / "hb")
    monkeypatch.setattr(archive_sync.Sync, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(archive_sync.Sync, "run_once", lambda self: {"imported": 3})
    call_command("sync_archive_to_mailbox", "--once")
    assert (tmp_path / "hb").exists()
    monkeypatch.setattr(archive_sync.Sync, "run_once", lambda self: (_ for _ in ()).throw(RuntimeError("secret")))
    call_command("sync_archive_to_mailbox", "--once")


class OkGmail:
    def check(self):
        return 12


class BadGmail:
    def check(self):
        raise gmail.GoogleError("Google refused: the mailbox is not authorised for the two Gmail permissions (insert and labels), or the credential is wrong.")


def by_key(checks):
    return {c.key: c for c in checks}


def test_the_setup_check_reports_a_working_credential_and_a_running_sync():
    ArchiveSyncState.objects.create(pk=1, last_ok_at=NOW - timedelta(minutes=3), last_run_at=NOW)
    c = by_key(setupcheck._archive_sync_checks(NOW, OkGmail()))
    assert c["mcred"].status == "ok" and c["mrun"].status == "ok" and "info@corp.example" in c["mcred"].detail and "mfail" not in c


def test_the_setup_check_fails_plainly_for_a_bad_credential_without_leaking():
    c = by_key(setupcheck._archive_sync_checks(NOW, BadGmail()))
    assert c["mcred"].status == "fail" and "not authorised" in c["mcred"].detail and c["mcred"].fix


def test_the_setup_check_warns_when_nothing_has_run_or_the_sync_stopped_keeping_up():
    assert by_key(setupcheck._archive_sync_checks(NOW, OkGmail()))["mrun"].status == "warn"
    ArchiveSyncState.objects.create(pk=1, last_ok_at=NOW - timedelta(hours=3))
    assert by_key(setupcheck._archive_sync_checks(NOW, OkGmail()))["mrun"].status == "warn"


def test_the_setup_check_distinguishes_messages_waiting_for_a_retry_from_ones_that_gave_up():
    ArchiveSyncItem.objects.create(archived_message_id="a", state="failed", attempts=2)
    assert by_key(setupcheck._archive_sync_checks(NOW, OkGmail()))["mfail"].status == "warn"
    ArchiveSyncItem.objects.create(archived_message_id="b", state="failed", attempts=archive_sync.MAX_ATTEMPTS)
    assert by_key(setupcheck._archive_sync_checks(NOW, OkGmail()))["mfail"].status == "fail"


def test_the_group_appears_in_the_setup_check_only_when_the_copy_is_on(settings):
    settings.SQS_EVENTS_QUEUE_URL = "https://sqs.ap-south-1.amazonaws.com/111122223333/mc-events"
    settings.ARCHIVE_SYNC_ENABLED = False
    assert not [c for c in setupcheck.run_checks("ap-south-1") if c.group == "Mailbox copy"]
    settings.ARCHIVE_SYNC_ENABLED = True
    assert [c for c in setupcheck.run_checks("ap-south-1", gmail=OkGmail()) if c.group == "Mailbox copy"]


def test_a_stalled_sync_and_stuck_messages_open_alerts_that_resolve_when_fixed():
    now = datetime.now(timezone.utc)
    ArchiveSyncState.objects.create(pk=1, last_ok_at=now - timedelta(hours=5))
    ArchiveSyncItem.objects.create(archived_message_id="a", state="failed", attempts=archive_sync.MAX_ATTEMPTS)
    alerts.evaluate(), alerts.evaluate()
    assert Alert.objects.filter(key="archive_sync_stalled", resolved_at__isnull=True).count() == 1 and Alert.objects.filter(key="archive_sync_failed", resolved_at__isnull=True).count() == 1
    ArchiveSyncState.objects.update(last_ok_at=now)
    ArchiveSyncItem.objects.update(state="imported")
    alerts.evaluate()
    assert not Alert.objects.filter(key__startswith="archive_sync", resolved_at__isnull=True).exists()


def test_no_alert_when_the_copy_is_off_even_with_old_state(settings):
    settings.ARCHIVE_SYNC_ENABLED = False
    ArchiveSyncState.objects.create(pk=1, last_ok_at=datetime.now(timezone.utc) - timedelta(days=3))
    ArchiveSyncItem.objects.create(archived_message_id="a", state="failed", attempts=99)
    alerts.evaluate()
    assert not Alert.objects.filter(key__startswith="archive_sync").exists()


# ---------------------------------------------------------------- configuration
def _config(**env):
    base = {"MC_SECRET_KEY": "x" * 60, "MC_DEBUG": "0", "MC_CONSOLE_HOST": "console.test", "MC_MAILVIEW_HOST": "mailview.test", "MC_DB_PORT": "54329",
            "MC_WEBAUTHN_ORIGIN": "https://console.test", "MC_MAIL_ARCHIVE_ID": "a-abc123"}
    code = "import os; os.environ['DJANGO_SETTINGS_MODULE']='config.settings'; from config import settings; print(settings.ARCHIVE_SYNC_ENABLED)"
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env={**os.environ, **base, **env}, capture_output=True, text=True)


GOOD = {"MC_ARCHIVE_SYNC_MAILBOX": "info@corp.example", "MC_GOOGLE_SERVICE_ACCOUNT_FILE": "/run/secrets/key.json"}
OAUTH = {"MC_ARCHIVE_SYNC_MAILBOX": "info@corp.example", "MC_GOOGLE_OAUTH_CLIENT_ID": "c", "MC_GOOGLE_OAUTH_CLIENT_SECRET": "s", "MC_GOOGLE_OAUTH_REFRESH_TOKEN": "r"}


def test_the_copy_is_off_by_default_and_either_kind_of_credential_turns_it_on():
    assert _config().stdout.strip() == "False" and _config(**GOOD).stdout.strip() == "True" and _config(**OAUTH).stdout.strip() == "True"


@pytest.mark.parametrize("bad", [
    {"MC_ARCHIVE_SYNC_MAILBOX": "*@corp.example"}, {"MC_ARCHIVE_SYNC_MAILBOX": "not-an-address"},
    {"MC_MAIL_ARCHIVE_ID": ""},                                                                  # the copy is made from the archive
    {"MC_GOOGLE_SERVICE_ACCOUNT_FILE": ""},                                                      # no credential at all
    {"MC_GOOGLE_OAUTH_CLIENT_ID": "c", "MC_GOOGLE_OAUTH_CLIENT_SECRET": "s", "MC_GOOGLE_OAUTH_REFRESH_TOKEN": "r"},   # both kinds
    {"MC_ARCHIVE_SYNC_LABEL_ROOT": "Inbox"}, {"MC_ARCHIVE_SYNC_LABEL_ROOT": "sent"}, {"MC_ARCHIVE_SYNC_LABEL_ROOT": "a/b"}, {"MC_ARCHIVE_SYNC_LABEL_ROOT": ""},
    {"MC_ARCHIVE_SYNC_INTERVAL": "10"}, {"MC_ARCHIVE_SYNC_INTERVAL": "100000"},
])
def test_a_bad_configuration_stops_the_app_from_starting(bad):
    proc = _config(**{**GOOD, **bad})
    assert proc.returncode != 0 and "mailbox copy is enabled but not configured correctly" in proc.stderr, bad


def test_a_partial_oauth_credential_is_refused():
    proc = _config(MC_ARCHIVE_SYNC_MAILBOX="info@corp.example", MC_GOOGLE_OAUTH_CLIENT_ID="c", MC_GOOGLE_OAUTH_CLIENT_SECRET="s")
    assert proc.returncode != 0 and "mailbox copy is enabled" in proc.stderr


def test_the_migrations_match_the_models():
    from io import StringIO
    out = StringIO()
    try:
        call_command("makemigrations", "--check", "--dry-run", stdout=out, stderr=out)
    except SystemExit:
        pytest.fail("models and migrations differ: " + out.getvalue())
