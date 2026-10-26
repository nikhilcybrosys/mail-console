"""Copy every message in an SES mail archive into a Google Workspace mailbox, once.

The archive holds the original of each message for its retention period (at least three months). This keeps a permanent copy in a
mailbox you can search like any other: it scans the archive in time windows, downloads each message's original, and inserts it (see
gmail.py) under a label per sending address. Nothing is sent. A record per message (`ArchiveSyncItem`, metadata only) makes a repeated
run harmless and lets failed messages be retried; the scan point (`ArchiveSyncState`) means a quiet archive costs one small search.

Why each safeguard is there:
* The newest hour is always scanned again and the scan starts a second early, so a message archived late, or exactly on a window edge,
  is not missed; the unique archived-message id stops it being imported twice.
* A window with as many results as the search returns at most is split until it no longer is, so none are cut off.
* Failures are recorded and retried a limited number of times (at most once per pass), and never stop the other messages or the scan.
"""
import logging
import re
import time
from datetime import timedelta
from email.utils import parseaddr
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.utils import timezone

from . import archive
from .gmail import Auth, Gmail, GoogleError
from .models import ArchiveSyncItem, ArchiveSyncState

log = logging.getLogger(__name__)
MAX_RAW = 10 * 1024 * 1024        # larger messages are skipped and recorded, not imported
CHUNK = timedelta(days=1)
RESCAN = timedelta(hours=1)
LAG = timedelta(minutes=1)
MIN_WINDOW = timedelta(seconds=2)
MAX_ATTEMPTS = 8
DOWNLOAD_TRIES = 5                  # S3 answers "access denied" to a fraction of requests for the same download link, and the next one works
INCOMPLETE_SHOWN = timedelta(days=14)   # how long an incomplete window is flagged (the archive still holds the originals)


def label_name(from_header):
    """'Acme <ops-watchdog@example.com>' -> 'Ops-Watchdog'. Only letters and digits survive, so the name is always a valid label."""
    local = parseaddr(from_header or "")[1].split("@")[0].lower()
    words = [w for w in re.split(r"[^a-z0-9]+", local) if w]
    return "-".join(w.capitalize() for w in words)[:60] or "Other"


class DownloadRefused(archive.ArchiveError):
    """The download link answered with something other than the message. `status` says what (403 and 5xx are worth trying again)."""

    def __init__(self, status):
        super().__init__("The archived message could not be downloaded.")
        self.status = status


def download(url, get=requests.get):
    """The original message from the short-lived link the archive gives. https only, size-capped."""
    if urlparse(url).scheme != "https":
        raise archive.ArchiveError("The archive gave a download link that is not https.")
    with get(url, timeout=30, stream=True) as resp:
        if resp.status_code != 200:
            raise DownloadRefused(resp.status_code)
        chunks, size = [], 0
        for chunk in resp.iter_content(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RAW:      # stop reading: it is too large to import, and the caller records that
                break
    return b"".join(chunks)


class Sync:
    def __init__(self, reader=None, gmail=None, fetch=None, sleep=time.sleep):
        self.reader = reader or archive.Reader()
        self.gmail = gmail or Gmail(Auth.from_settings(settings))
        self.fetch = fetch or download
        self._sleep = sleep
        self.stats = {"imported": 0, "failed": 0, "skipped": 0, "windows": 0}
        self._tried = set()          # messages attempted in this pass: each is tried at most once per pass, so retries do not burn attempts
        self.incomplete = []         # (start, end) of windows that still held more messages than one search returns, even split by sender

    # ---------------------------------------------------------------- one message
    @staticmethod
    def _short(exc):
        return str(exc)[:190] if isinstance(exc, (GoogleError, archive.ArchiveError)) else exc.__class__.__name__

    def _original(self, archived_message_id):
        """The message's original bytes. A refused download (403 or a server error) is retried with a FRESH link, a few times; anything else is not."""
        for attempt in range(DOWNLOAD_TRIES):
            link = self.reader.mm.get_archive_message(ArchivedMessageId=archived_message_id)["MessageDownloadLink"]
            try:
                return self.fetch(link)
            except DownloadRefused as exc:
                if (exc.status != 403 and exc.status < 500) or attempt == DOWNLOAD_TRIES - 1:
                    raise
                self._sleep(attempt + 1)

    def _attempt(self, item, row):
        if item.archived_message_id in self._tried:
            return
        self._tried.add(item.archived_message_id)
        item.attempts += 1
        try:
            raw = self._original(item.archived_message_id)
            if len(raw) > MAX_RAW:
                item.state, item.detail, item.done_at = ArchiveSyncItem.SKIPPED, "larger than 10 MB, not imported", timezone.now()
                self.stats["skipped"] += 1
            else:
                root = settings.ARCHIVE_SYNC_LABEL_ROOT
                labels = [self.gmail.label(root), self.gmail.label(f"{root}/{label_name(row.get('From') if row else item.from_addr)}")]
                item.gmail_id, item.state, item.detail, item.done_at = self.gmail.insert(raw, labels), ArchiveSyncItem.IMPORTED, "", timezone.now()
                self.stats["imported"] += 1
        except Exception as exc:  # noqa: BLE001: one bad message never stops the others; the reason is recorded, the mail is retried
            item.state, item.detail = ArchiveSyncItem.FAILED, self._short(exc)
            self.stats["failed"] += 1
            if not isinstance(exc, (GoogleError, archive.ArchiveError, requests.RequestException)):
                log.warning("archive sync: unexpected failure (%s)", exc.__class__.__name__)
        item.save()

    def _handle(self, row):
        item, _ = ArchiveSyncItem.objects.get_or_create(
            archived_message_id=row["ArchivedMessageId"],
            defaults={"state": ArchiveSyncItem.FAILED, "message_id_header": (row.get("MessageId") or "")[:300], "from_addr": parseaddr(row.get("From") or "")[1][:320]})
        if item.state == ArchiveSyncItem.FAILED and item.attempts < MAX_ATTEMPTS:
            self._attempt(item, row)

    # ---------------------------------------------------------------- scanning
    @staticmethod
    def _union(*lists):
        seen, out = set(), []
        for rows in lists:
            for r in rows:
                if r["ArchivedMessageId"] not in seen:
                    seen.add(r["ArchivedMessageId"])
                    out.append(r)
        return out

    def _rows(self, start, end):
        self.stats["windows"] += 1
        rows = self.reader._search(start, end)
        if len(rows) < archive.MAX_RESULTS:
            return rows
        if end - start > MIN_WINDOW:
            mid = start + (end - start) / 2
            return self._union(self._rows(start, mid), self._rows(mid, end))
        # Too many messages in the smallest window to tell apart by time. Ask for each sender seen there on its own, then for everything
        # that is NOT from those senders. All of it is imported, but the window is only called complete when that is PROVEN: at most 10
        # senders, none of them filling a search by itself, and nothing else left over. (With more than 10 senders something is always
        # left over, because the archive can exclude no more than 10 in one search.) In every other case it is recorded as incomplete, shown in the Setup check and alerted, never reported as a clean
        # pass. (Excluding a sender also excludes any address containing it as text; a freak overlap like that can hide a sender.)
        asked = self._senders(rows)
        parts, proven = [rows], True
        for sender in asked:
            part = self.reader._search(start, end, sender=sender)
            parts.append(part)
            proven = proven and len(part) < archive.MAX_RESULTS
        rest = self.reader._search(start, end, exclude_senders=asked)       # the reader clips this to what the archive accepts (10)
        if rest:
            parts.append(rest)
            proven = False      # something was left over: the first look missed a sender, so completeness cannot be shown
        if not proven:
            self.incomplete.append((start, end))
        return self._union(*parts)

    @staticmethod
    def _senders(rows):
        out = []
        for r in rows:
            s = (r.get("Envelope") or {}).get("From") or r.get("From") or ""
            if s and s not in out:
                out.append(s)
        return out

    def retry_failed(self):
        for item in ArchiveSyncItem.objects.filter(state=ArchiveSyncItem.FAILED, attempts__lt=MAX_ATTEMPTS).order_by("first_seen")[:200]:
            self._attempt(item, None)

    def run_once(self, now=None):
        now = now or timezone.now()
        state, _ = ArchiveSyncState.objects.get_or_create(pk=1)
        state.last_run_at = now
        end = now - LAG
        if state.scanned_to is None:
            created = self.reader.mm.get_archive(ArchiveId=self.reader.archive_id).get("CreatedTimestamp")
            start = (created or now - timedelta(days=100)) - timedelta(minutes=1)
        else:
            start = state.scanned_to - RESCAN
        start -= timedelta(seconds=1)
        failed_before = self.stats["failed"]
        cursor = start
        while cursor < end:
            window_end = min(cursor + CHUNK, end)
            for row in self._rows(cursor, window_end):
                self._handle(row)
            cursor = window_end
        self.retry_failed()
        state.scanned_to = end
        if self.incomplete:
            state.incomplete_at, state.incomplete_windows = now, state.incomplete_windows + len(self.incomplete)
            log.warning("archive sync: %s window(s) held more messages than a search returns: %s", len(self.incomplete), self.incomplete[:3])
        if self.stats["failed"] == failed_before and not self.incomplete:
            state.last_ok_at = now
        state.save()
        return self.stats
