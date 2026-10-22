import pytest
from django.test import Client

from apps.sesdata.management.commands.ingest_ses_events import Command


def test_healthz_answers_for_any_host_without_a_session_or_database():
    r = Client(HTTP_HOST="10.0.12.34").get("/healthz/")  # a task IP, not in ALLOWED_HOSTS
    assert r.status_code == 200 and r.content == b"ok" and "Set-Cookie" not in r.headers
    assert Client(HTTP_HOST="10.0.12.34").post("/healthz/").status_code != 200  # only GET/HEAD


def test_other_paths_still_reject_unknown_hosts():
    assert Client(HTTP_HOST="evil.example").get("/login/").status_code == 400


def test_worker_refreshes_its_heartbeat_file_every_cycle(tmp_path, settings):
    settings.WORKER_HEARTBEAT_FILE = str(tmp_path / "hb")

    class Sqs:
        def receive_message(self, **kw):
            return {}
    Command().drain(Sqs(), "queue-url")
    assert (tmp_path / "hb").exists()
