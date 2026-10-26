"""Read the text of mail that Amazon SES archived.

SES can copy every message sent through a configuration set into an SES Mail Manager archive (set up once, in AWS; see
aws/README.md). SES publishes no message content in its events, so this archive is the only place the text of mail sent by other
applications exists. The console reads it on demand, for one message at a time:

1. Find the message. The archive can be searched by time window and by address, not by message id, so the search covers the few
   minutes around the send and the result is matched on the Message-ID header (which SES sets to <SES message id>@<region>.amazonses.com).
2. Fetch its content, turn HTML into plain text, and redact secrets (links with tokens, one-time codes) before it is shown.

Nothing is stored in the console's database. Errors are reported in plain words; AWS error text is never passed on.
"""
import logging
import re
import time
from datetime import timedelta
from html.parser import HTMLParser

import boto3
from django.conf import settings

from apps.inbound.redact import redact_text

log = logging.getLogger(__name__)
WINDOW_BEFORE = timedelta(minutes=5)     # an archived copy is received at about the time the message is sent
WINDOW_AFTER = timedelta(minutes=30)
MAX_RESULTS = 50
POLL_SECONDS = 2
MAX_TEXT = 200_000                       # characters shown; longer text is cut with a note
_ID = re.compile(r"[A-Za-z0-9._=+-]{1,200}")


class ArchiveError(Exception):
    """A problem to show the person in plain words. Never carries AWS error text."""


class NotArchived(ArchiveError):
    pass


def client():
    return boto3.client("mailmanager", region_name=settings.AWS_REGIONS[0])


def _ses_id(header):
    """'<id@region.amazonses.com>' -> 'id'"""
    return (header or "").strip().strip("<>").split("@")[0]


class Reader:
    def __init__(self, mm=None, archive_id=None, sleep=time.sleep, timeout=25):
        self.mm = mm or client()
        self.archive_id = archive_id or settings.MAIL_ARCHIVE_ID
        self._sleep, self.timeout = sleep, timeout

    # -------------------------------------------------------------- find
    def _search(self, start, end, recipient=None):
        kw = {"ArchiveId": self.archive_id, "FromTimestamp": start, "ToTimestamp": end, "MaxResults": MAX_RESULTS}
        if recipient:
            kw["Filters"] = {"Include": [{"StringExpression": {"Evaluate": {"Attribute": "ENVELOPE_TO"}, "Operator": "CONTAINS", "Values": [recipient[:2048]]}}]}
        search_id = self.mm.start_archive_search(**kw)["SearchId"]
        waited = 0
        while True:
            state = self.mm.get_archive_search(SearchId=search_id).get("Status", {}).get("State", "")
            if state == "COMPLETED":
                return self.mm.get_archive_search_results(SearchId=search_id).get("Rows", [])
            if state in ("FAILED", "CANCELLED"):
                raise ArchiveError("The archive could not be searched. Try again in a moment.")
            if waited >= self.timeout:
                raise ArchiveError("The archive took too long to answer. Try again in a moment.")
            self._sleep(POLL_SECONDS)
            waited += POLL_SECONDS

    def find(self, ses_message_id, sent_at, recipient=None):
        """The archive's row for this SES message: {'ArchivedMessageId', 'From', 'To', 'Subject', 'Date', ...}. Raises NotArchived."""
        if not _ID.fullmatch(ses_message_id or ""):
            raise NotArchived("This message has no usable id.")
        start, end = sent_at - WINDOW_BEFORE, sent_at + WINDOW_AFTER
        rows = self._search(start, end)
        match = next((r for r in rows if _ses_id(r.get("MessageId")) == ses_message_id), None)
        if match is None and len(rows) >= MAX_RESULTS and recipient:
            # A busy window can hide the message beyond the result limit: ask for this recipient only.
            match = next((r for r in self._search(start, end, recipient) if _ses_id(r.get("MessageId")) == ses_message_id), None)
        if match is None:
            raise NotArchived("No archived copy of this message was found. It may have been sent before archiving was switched on, "
                              "through a configuration set that is not archived, or it may not have reached the archive yet.")
        return match

    # -------------------------------------------------------------- read
    def content(self, archived_message_id):
        body = self.mm.get_archive_message_content(ArchivedMessageId=archived_message_id).get("Body", {})
        return {"text": body.get("Text") or "", "html": body.get("Html") or "", "malformed": bool(body.get("MessageMalformed"))}


class _Text(HTMLParser):
    """HTML -> plain text: no scripts, styles or comments; block elements become line breaks; link targets are dropped."""

    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "article", "ul", "ol", "hr"}
    SKIP = {"script", "style", "head", "title"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self._skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self._skip = max(self._skip - 1, 0)
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.out.append(data)


def html_to_text(html):
    p = _Text()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001: hostile markup can confuse the parser; fall back to nothing rather than raw markup
        return ""
    text = "".join(p.out).replace("\xa0", " ")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" ?\n ?", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


_QUERY = re.compile(r"(https?://[^\s<>\"'?#]+)\?[^\s<>\"']*", re.I)
_FRAGMENT = re.compile(r"(https?://[^\s<>\"'#]+)#[^\s<>\"']*", re.I)
# A long unbroken run after a "/" (a link's path: tokens, ids and signed names), except the host, which directly follows "://".
_OPAQUE = re.compile(r"(?<!://)(?<=/)[A-Za-z0-9_~.-]{24,}(?=[/\s<>\"'?#]|$)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def redact_for_display(text, extra_rules=()):
    """The shared secret redaction, plus: every link's query string and fragment, any long opaque path segment and any JWT is masked.
    Mail from other applications routinely carries sign-in, invitation and reset links, and the console has no way to tell which are
    sensitive. `extra_rules` are the regular expressions of the message's mail category, if it has any (invalid ones are ignored)."""
    text = redact_text(text, extra_rules)
    text = _QUERY.sub(r"\1?[redacted]", text)
    text = _FRAGMENT.sub(r"\1#[redacted]", text)
    text = _JWT.sub("[redacted]", text)
    return _OPAQUE.sub("[redacted]", text)


def readable(content, extra_rules=()):
    """-> (text, note). The plain-text part if the message has one, otherwise the HTML turned into text; always redacted."""
    text = content["text"] or html_to_text(content["html"])
    note = ""
    if content["malformed"]:
        note = "AWS marked this message as malformed, so parts of it may be missing."
    if len(text) > MAX_TEXT:
        text, note = text[:MAX_TEXT], (note + " " if note else "") + f"The text was cut after {MAX_TEXT:,} characters."
    return redact_for_display(text, extra_rules), note
