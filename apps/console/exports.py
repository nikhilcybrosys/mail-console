"""CSV exports and saved sent-mail views.

Exports hold recipient addresses, so they are gated like other sensitive reads (a capability, a fresh passkey, an audit
row, a row cap) and written defensively: every cell is neutralised against spreadsheet formula injection, the response
is streamed so a large export does not sit in memory, and it is never cached.
"""
import csv
from datetime import timezone as dt_timezone
from urllib.parse import urlencode

from django.http import StreamingHttpResponse
from django.utils import timezone

# ---------------------------------------------------------------- CSV
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """A cell that a spreadsheet will show as text. Text starting with = + - @ (or a tab/CR) can be run as a formula
    by Excel, LibreOffice and Sheets, and the recipient or subject of an email is chosen by someone else, so such a
    cell gets a leading apostrophe (the OWASP-recommended neutralisation). Everything else is untouched."""
    if value is None:
        return ""
    s = str(value)
    return "'" + s if s.startswith(_FORMULA_START) else s


def iso(dt):
    return dt.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


class _Echo:
    def write(self, value):
        return value


def csv_response(prefix, header, rows):
    """Stream `rows` (iterables of cell values) as a CSV download. The filename never contains user input."""
    writer = csv.writer(_Echo(), lineterminator="\r\n")

    def body():
        yield "﻿"  # byte-order mark: Excel opens UTF-8 (names, subjects) correctly
        yield writer.writerow(header)
        for row in rows:
            yield writer.writerow([csv_safe(c) for c in row])

    resp = StreamingHttpResponse(body(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{prefix}-{timezone.now().strftime("%Y%m%d-%H%M")}.csv"'
    resp["Cache-Control"] = "no-store"
    return resp


MESSAGE_HEADER = ["sent_at_utc", "message_id", "from", "recipient", "recipient_status", "message_status", "subject", "app",
                  "category", "config_set", "last_event_utc"]


def message_rows(messages):
    """One row per recipient (a message to three people is three rows). `messages` is a queryset."""
    for m in messages.prefetch_related("recipients").iterator(chunk_size=500):
        base = [iso(m.sent_at), m.ses_message_id, m.from_addr]
        tail = [m.final_state, m.subject, m.source_app, m.mail_category, m.config_set]
        recipients = list(m.recipients.all())
        if not recipients:
            yield base + [""] + [""] + tail + [""]
        for r in recipients:
            yield base + [r.address, r.state] + tail + [iso(r.last_event_at)]


SUPPRESSION_HEADER = ["address", "reason", "last_updated_utc"]


def suppression_rows(entries):
    for e in entries.iterator(chunk_size=1000):
        yield [e.address, e.reason, iso(e.last_update_time)]


# ---------------------------------------------------------------- saved views
# Only the parameters the sent-mail page understands are kept, so a saved view can never carry anything else.
VIEW_KEYS = ("q", "state", "app", "config_set", "domain", "category", "days", "sort", "dir")
MAX_VIEWS_PER_USER = 20
MAX_VALUE = 120


def canonical_params(querydict):
    """The saved form of a filter set: whitelisted, non-empty, bounded, in a fixed order (so equal views compare equal)."""
    pairs = []
    for k in VIEW_KEYS:
        v = (querydict.get(k) or "").strip()[:MAX_VALUE]
        if v:
            pairs.append((k, v))
    return urlencode(pairs)
