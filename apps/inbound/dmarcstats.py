"""What the DMARC page shows: per-domain pass rates, who is sending as the domain, and whether it looks safe to tighten the policy.

"Passing" means DMARC-aligned: DKIM or SPF passed AND aligned (that is what the reporting provider's `policy_evaluated` says).
"""
from datetime import timedelta

from django.db.models import Exists, OuterRef
from django.utils import timezone

from .models import DmarcMail, DmarcReport

PERIODS = (7, 30, 90)
MIN_MESSAGES = 100
MIN_DAYS = 7
READY_FAIL_RATE = 0.02
TOP_SOURCES = 25


def _recent(days, now=None):
    """Reports in the period. A report that is also present as a verified mail copy is counted once, as that copy."""
    now = now or timezone.now()
    twin = DmarcReport.objects.filter(source="inbox", org_name=OuterRef("org_name"), report_id=OuterRef("report_id"))
    return DmarcReport.objects.filter(end__gte=now - timedelta(days=days)).exclude(Exists(twin), source__in=("upload", "mail"))


def days_covered(reports):
    """Distinct calendar days (UTC) that at least one report's date range touches."""
    seen = set()
    for begin, end in reports.values_list("begin", "end"):
        d = begin.date()
        while d <= end.date() and len(seen) < 400:
            seen.add(d)
            d += timedelta(days=1)
    return len(seen)


def readiness(policy, total, failed, covered):
    """-> (state, text). state: enforcing | not_enough | ready | not_ready. Advice, never an instruction."""
    if policy in ("quarantine", "reject"):
        return "enforcing", f"Already enforcing (p={policy}). Keep watching the failing sources below."
    if covered < MIN_DAYS or total < MIN_MESSAGES:
        return "not_enough", f"Not enough data yet: wait for at least {MIN_DAYS} days of reports and {MIN_MESSAGES} messages (you have {covered} days and {total} messages)."
    rate = failed / total
    if rate <= READY_FAIL_RATE:
        return "ready", (f"{(1 - rate) * 100:.1f}% of messages pass. Check the failing sources below are not something you need, then move to "
                         "p=quarantine, ideally with pct=10 first and raising it over a few weeks.")
    return "not_ready", f"{rate * 100:.1f}% of messages fail DMARC. Fix the failing sources below (add them to SPF, or set up DKIM for them) before enforcing."


def overview(days=30, now=None):
    reports = _recent(days, now)
    out = []
    for domain in sorted(set(reports.values_list("domain", flat=True))):
        rs = reports.filter(domain=domain)
        ok = sum(rs.values_list("pass_count", flat=True))
        bad = sum(rs.values_list("fail_count", flat=True))
        latest = rs.order_by("-end").first()
        covered = days_covered(rs)
        state, text = readiness(latest.policy, ok + bad, bad, covered)
        uploaded, unlisted = rs.filter(source="upload").count(), rs.filter(source="mail").count()
        if uploaded and state in ("ready", "not_ready"):
            text += (f" Note: {uploaded} of these {rs.count()} reports were uploaded by hand and are taken at face value; the console cannot verify"
                     " they came from the provider.")
        if unlisted and state in ("ready", "not_ready"):
            text += (f" Note: {unlisted} of these {rs.count()} reports came by mail from senders you have not listed as reporting providers, so"
                     " the console cannot tell they are genuine.")
        out.append({"domain": domain, "policy": latest.policy, "reports": rs.count(), "passed": ok, "failed": bad, "total": ok + bad,
                    "pass_rate": (ok / (ok + bad)) if ok + bad else 0.0, "days": covered, "state": state, "advice": text,
                    "providers": sorted(set(rs.values_list("org_name", flat=True))), "uploaded": uploaded, "unlisted": unlisted})
    return out


def sources(domain, days=30, now=None):
    """Who is sending as `domain`: one row per (IP, From domain), failing ones first."""
    agg = {}
    for rows in _recent(days, now).filter(domain=domain).values_list("rows", flat=True):
        for r in rows:
            key = (r["source_ip"], r.get("header_from", ""))
            a = agg.setdefault(key, {"ip": key[0], "header_from": key[1], "count": 0, "passed": 0, "failed": 0, "dkim_pass": 0, "spf_pass": 0, "dispositions": set()})
            a["count"] += r["count"]
            if r["dkim"] == "pass" or r["spf"] == "pass":
                a["passed"] += r["count"]
            else:
                a["failed"] += r["count"]
            if r["dkim"] == "pass":
                a["dkim_pass"] += r["count"]
            if r["spf"] == "pass":
                a["spf_pass"] += r["count"]
            if r.get("disposition"):
                a["dispositions"].add(r["disposition"])
    rows = sorted(agg.values(), key=lambda a: (-a["failed"], -a["count"], a["ip"]))
    for a in rows:
        a["dispositions"] = sorted(a["dispositions"])
    return rows[:TOP_SOURCES], max(len(rows) - TOP_SOURCES, 0)


def recent_reports(domain=None, limit=25, days=None, now=None):
    qs = (_recent(days, now) if days else DmarcReport.objects.all()).order_by("-end")
    if domain:
        qs = qs.filter(domain=domain)
    return list(qs[:limit])


COLLECTION_DAYS = 7
SILENT_AFTER = timedelta(hours=72)


def collection(enabled, now=None):
    """The "Collection" card: is mail delivery of reports working, and what was turned away? None when there is nothing to show."""
    now = now or timezone.now()
    week = DmarcMail.objects.filter(created_at__gte=now - timedelta(days=COLLECTION_DAYS))
    if not enabled and not DmarcMail.objects.exists():
        return None
    last = DmarcMail.objects.exclude(outcome="refused").order_by("-received_at").values_list("received_at", flat=True).first()
    counts = {o: week.filter(outcome=o).count() for o in ("accepted", "duplicate", "refused")}
    unlisted = sorted(set(DmarcReport.objects.filter(source="mail", end__gte=now - timedelta(days=30)).values_list("sender", flat=True)))
    return {"enabled": enabled, "last": last, "silent": bool(enabled and last and now - last > SILENT_AFTER), **counts,
            "refusals": list(week.filter(outcome="refused").order_by("-received_at")[:10]), "unlisted_senders": unlisted}
