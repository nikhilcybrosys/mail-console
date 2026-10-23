"""Add DMARC aggregate reports that a person uploads: the xml / .gz / .zip attachments mailbox providers e-mail to your rua address.

Untrusted input, so: size limits before reading, decompression capped by apps.inbound.dmarc (defusedxml, no DTDs or entities),
every field validated and normalised, anything unexpected rejects the whole report, and only reports for domains this console
watches are accepted. The raw file is never stored; only the validated numbers are.
"""
import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import dmarc
from .models import DmarcReport

log = logging.getLogger(__name__)
MAX_FILES = 10
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ROWS = 5000
MAX_COUNT = 10 ** 9
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_RESULTS = {"pass", "fail", "none", "neutral", "softfail", "temperror", "permerror", ""}
_DISPOSITIONS = {"none", "quarantine", "reject", ""}
_POLICIES = {"none", "quarantine", "reject", ""}


@dataclass
class Result:
    filename: str
    status: str  # added | duplicate | error
    detail: str = ""
    domain: str = ""


def watched_domains():
    """Domains of the verified sending identities the console has synced (a bare address identity counts by its domain)."""
    from apps.sesdata.models import IdentitySnapshot
    seen = {}
    for row in IdentitySnapshot.objects.order_by("taken_at"):
        seen[(row.region, row.identity)] = row
    out = set()
    for (_, ident), row in seen.items():
        out.add(ident.lower().split("@")[-1])
    return out


def domain_ok(domain, allowed):
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def _text(value, limit):
    return _CONTROL.sub(" ", value or "").strip()[:limit]


def clean_report(parsed, now=None):
    """Validate and normalise what the parser returned. Raises DmarcError with a plain reason if anything is off."""
    now = now or timezone.now()
    org, rid = _text(parsed.get("org_name"), 200), _text(parsed.get("report_id"), 200)
    domain = (parsed.get("domain") or "").strip().lower()
    if not org or not rid:
        raise dmarc.DmarcError("the report has no sender organisation or report id")
    if not _HOST.match(domain):
        raise dmarc.DmarcError("the report's domain is not valid")
    begin, end = parsed["begin"], parsed["end"]
    if end < begin or end - begin > timedelta(days=366) or begin.year < 2000 or end > now + timedelta(days=2):
        raise dmarc.DmarcError("the report's date range is not plausible")
    if len(parsed["rows"]) > MAX_ROWS:
        raise dmarc.DmarcError(f"the report has more than {MAX_ROWS} records")
    rows, ok, bad = [], 0, 0
    for r in parsed["rows"]:
        try:
            ip = str(ipaddress.ip_address((r.get("source_ip") or "").strip()))
        except ValueError:
            raise dmarc.DmarcError("the report contains a source address that is not an IP address") from None
        count = r.get("count")
        if not isinstance(count, int) or not 0 <= count <= MAX_COUNT:
            raise dmarc.DmarcError("the report contains an invalid message count")
        dkim, spf, disp = (r.get("dkim") or "").lower(), (r.get("spf") or "").lower(), (r.get("disposition") or "").lower()
        if dkim not in _RESULTS or spf not in _RESULTS or disp not in _DISPOSITIONS:
            raise dmarc.DmarcError("the report contains a result value this console does not recognise")
        hf = (r.get("header_from") or "").strip().lower()
        rows.append({"source_ip": ip, "count": count, "disposition": disp, "dkim": dkim, "spf": spf, "header_from": hf if _HOST.match(hf) else ""})
        if dkim == "pass" or spf == "pass":
            ok += count
        else:
            bad += count
    policy = (parsed.get("policy") or "").lower()
    return {"org_name": org, "report_id": rid, "domain": domain, "policy": policy if policy in _POLICIES else "", "begin": begin, "end": end,
            "rows": rows, "pass_count": ok, "fail_count": bad}


def store_report(raw, name, *, source, allowed, now, uploader=""):
    """Validate one report file's bytes and store it. Returns a Result; never raises for bad input.

    `source` is "upload" (added by hand, unverified) or "inbox" (received by mail that passed the sender checks).
    """
    try:
        cleaned = clean_report(dmarc.parse(dmarc.unpack(raw, name)), now)
    except dmarc.DmarcError as exc:
        # The parser's "unparseable report: <ExceptionName>" is for logs; people get a plain sentence.
        why = "the file is not a valid DMARC aggregate report" if str(exc).startswith("unparseable") else str(exc)
        return Result(name, "error", why)
    except Exception as exc:  # noqa: BLE001: bad zip/gzip data, odd XML values: say "unreadable", log only the kind
        log.warning("dmarc %s: unreadable file (%s)", source, type(exc).__name__)
        return Result(name, "error", "the file could not be read as a DMARC report (xml, gz or zip)")
    if not domain_ok(cleaned["domain"], allowed):
        return Result(name, "error", f"{cleaned['domain']} is not one of the domains this console watches", cleaned["domain"])
    extra = {"uploaded_by": uploader, "uploaded_at": now} if source == "upload" else {}
    try:
        with transaction.atomic():
            DmarcReport.objects.create(source=source, file_sha256=hashlib.sha256(raw).hexdigest(), **extra, **cleaned)
    except IntegrityError:
        return Result(name, "duplicate", "already added", cleaned["domain"])
    return Result(name, "added", f"{cleaned['pass_count'] + cleaned['fail_count']} messages from {cleaned['org_name']}", cleaned["domain"])


def ingest(files, uploader, *, allowed=None, now=None):
    """Process uploaded files one by one; one bad file never stops the others. Returns a list of Result."""
    now = now or timezone.now()
    allowed = watched_domains() if allowed is None else allowed
    results = []
    for f in files:
        name = _text(getattr(f, "name", "") or "report", 120)
        if f.size > MAX_FILE_BYTES:
            results.append(Result(name, "error", f"larger than {MAX_FILE_BYTES // 1024 // 1024} MB"))
            continue
        raw = f.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            results.append(Result(name, "error", "file is too large"))
            continue
        results.append(store_report(raw, name, source="upload", allowed=allowed, now=now, uploader=uploader))
    return results
