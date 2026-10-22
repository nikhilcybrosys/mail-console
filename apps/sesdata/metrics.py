"""Aggregations for the dashboard. All read from our DB; reputation 'estimates' are labelled as such."""
import re
from datetime import timedelta

from django.conf import settings
from django.db.models import Count, Max, Q, Value
from django.db.models.functions import StrIndex, Substr
from django.utils import timezone

from .events import SUPPRESSION_SUBTYPES
from .models import Message, MessageEvent, MessageRecipient


def funnel(hours=24, now=None, **filters):
    now = now or timezone.now()
    since = now - timedelta(hours=hours)
    base = MessageRecipient.objects.filter(message__sent_at__gte=since, **filters)
    total = base.count()
    counts = dict(base.values_list("state").annotate(n=Count("id")).values_list("state", "n"))
    return {"since": since, "sent": total, "delivered": counts.get("delivery", 0), "bounced": counts.get("bounce", 0),
            "complained": counts.get("complaint", 0), "delayed": counts.get("deliverydelay", 0),
            "rejected": counts.get("reject", 0) + counts.get("renderingfailure", 0), "in_flight": counts.get("send", 0)}


def reputation_estimate(hours=24, now=None):
    """ESTIMATE only. SES computes its own rates on an undisclosed volume; CloudWatch Reputation.* is authoritative.

    Excludes suppression-driven bounces (they do not count toward SES reputation) and counts only
    permanent bounces. Returns rates as fractions plus the sample size.
    """
    now = now or timezone.now()
    since = now - timedelta(hours=hours)
    sent = MessageEvent.objects.filter(event_type="send", event_ts__gte=since).count()
    bounces = MessageEvent.objects.filter(event_type="bounce", event_ts__gte=since, payload__bounce__bounceType="Permanent") \
        .exclude(payload__bounce__bounceSubType__in=list(SUPPRESSION_SUBTYPES)).count()
    complaints = MessageEvent.objects.filter(event_type="complaint", event_ts__gte=since).count()
    return {"sample": sent, "bounce_rate": bounces / sent if sent else 0.0, "complaint_rate": complaints / sent if sent else 0.0,
            "bounces": bounces, "complaints": complaints}


def reputation_by_app(hours=24, now=None):
    """The same estimate as `reputation_estimate`, split by sender app (the `source_app` tag). Untagged mail is "(untagged)"."""
    now = now or timezone.now()
    since = now - timedelta(hours=hours)
    key = "message__source_app"

    def count(**filters):
        return {r[key] or "(untagged)": r["n"] for r in MessageEvent.objects.filter(event_ts__gte=since, **filters).values(key).annotate(n=Count("id"))}

    sent = count(event_type="send")
    bounces = {}
    for app, n in count(event_type="bounce", payload__bounce__bounceType="Permanent").items():
        bounces[app] = n
    suppression_driven = {r[key] or "(untagged)": r["n"] for r in MessageEvent.objects.filter(
        event_ts__gte=since, event_type="bounce", payload__bounce__bounceType="Permanent",
        payload__bounce__bounceSubType__in=list(SUPPRESSION_SUBTYPES)).values(key).annotate(n=Count("id"))}
    complaints = count(event_type="complaint")
    out = {}
    for app, n in sent.items():
        b = bounces.get(app, 0) - suppression_driven.get(app, 0)  # suppression-driven bounces do not count toward SES reputation
        out[app] = {"sample": n, "bounces": b, "complaints": complaints.get(app, 0),
                    "bounce_rate": b / n, "complaint_rate": complaints.get(app, 0) / n}
    return out


def send_count(config_set, days=7, now=None):
    now = now or timezone.now()
    return Message.objects.filter(config_set=config_set, sent_at__gte=now - timedelta(days=days), sent_at__lte=now).count()


def top_bounce_reasons(hours=168, limit=8, now=None):
    now = now or timezone.now()
    qs = MessageEvent.objects.filter(event_type="bounce", event_ts__gte=now - timedelta(hours=hours))
    rows = qs.values("payload__bounce__bounceType", "payload__bounce__bounceSubType").annotate(n=Count("id")).order_by("-n")[:limit]
    return [{"type": r["payload__bounce__bounceType"], "subtype": r["payload__bounce__bounceSubType"], "count": r["n"]} for r in rows]


def by_app(hours=168, now=None):
    now = now or timezone.now()
    return list(Message.objects.filter(sent_at__gte=now - timedelta(hours=hours)).values("source_app", "from_domain")
                .annotate(n=Count("id"), bad=Count("id", filter=Q(final_state__in=["bounce", "complaint"]))).order_by("-n")[:10])


def last_event_by_config_set():
    return dict(Message.objects.values("config_set").annotate(m=Max("events__event_ts")).values_list("config_set", "m"))


def hourly_series(hours=48, now=None):
    from django.db.models.functions import TruncHour
    now = now or timezone.now()
    qs = MessageEvent.objects.filter(event_ts__gte=now - timedelta(hours=hours), event_type__in=["send", "delivery", "bounce", "complaint"]) \
        .annotate(h=TruncHour("event_ts")).values("h", "event_type").annotate(n=Count("id")).order_by("h")
    series = {}
    for r in qs:
        series.setdefault(r["h"].isoformat(), {})[r["event_type"]] = r["n"]
    return series


# ---- Dashboard v2 helpers -------------------------------------------------------------------
def _floor(dt, step):
    dt = dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(hour=0) if step == "day" else dt


def series(hours=24, now=None):
    """Gap-filled time series of send/delivery/bounce/complaint counts.

    Hourly buckets up to 7 days, daily buckets beyond. Returns {"x": [epoch seconds], "send": [...], ...}.
    Bounces exclude suppression-driven ones (they do not count toward SES reputation).
    """
    from django.db.models.functions import TruncDay, TruncHour
    now = now or timezone.now()
    step = "day" if hours > 168 else "hour"
    delta = timedelta(days=1) if step == "day" else timedelta(hours=1)
    start = _floor(now - timedelta(hours=hours), step)
    trunc = TruncDay if step == "day" else TruncHour
    qs = MessageEvent.objects.filter(event_ts__gte=start, event_type__in=["send", "delivery", "bounce", "complaint"])
    qs = qs.exclude(event_type="bounce", payload__bounce__bounceSubType__in=list(SUPPRESSION_SUBTYPES))
    counts = {}
    for r in qs.annotate(b=trunc("event_ts")).values("b", "event_type").annotate(n=Count("id")):
        counts[(r["b"], r["event_type"])] = r["n"]
    xs, out = [], {"send": [], "delivery": [], "bounce": [], "complaint": []}
    t = start
    while t <= now:
        xs.append(int(t.timestamp()))
        for k in out:
            out[k].append(counts.get((t, k), 0))
        t += delta
    return {"x": xs, **out}


def period_totals(start, end):
    """Event totals in [start, end) for KPI tiles and deltas."""
    qs = MessageEvent.objects.filter(event_ts__gte=start, event_ts__lt=end)
    sent = qs.filter(event_type="send").count()
    delivered = qs.filter(event_type="delivery").count()
    bounced = qs.filter(event_type="bounce", payload__bounce__bounceType="Permanent") \
        .exclude(payload__bounce__bounceSubType__in=list(SUPPRESSION_SUBTYPES)).count()
    complained = qs.filter(event_type="complaint").count()
    rate = lambda n: (n / sent) if sent else 0.0  # noqa: E731
    return {"sent": sent, "delivered": delivered, "bounced": bounced, "complained": complained,
            "delivered_rate": rate(delivered), "bounce_rate": rate(bounced), "complaint_rate": rate(complained)}


def kpis(hours=24, now=None):
    """Current vs previous window, with the tone of a change decided here (up is good for delivery, bad for bounces)."""
    now = now or timezone.now()
    cur = period_totals(now - timedelta(hours=hours), now)
    prev = period_totals(now - timedelta(hours=2 * hours), now - timedelta(hours=hours))
    s = series(hours, now)

    def change(key, higher_is_good, as_points, neutral=False):
        a, b = cur[key], prev[key]
        if not prev["sent"] and not b:
            return {"text": "no prior data", "tone": "flat", "dir": "flat"}
        diff = (a - b) * 100 if as_points else ((a - b) / b * 100 if b else 100.0 if a else 0.0)
        if abs(diff) < 0.005:
            return {"text": "no change", "tone": "flat", "dir": "flat"}
        up = diff > 0
        good = up == higher_is_good
        if neutral:  # volume going up or down is not good or bad by itself
            return {"text": f"{abs(diff):.1f}%", "tone": "flat", "dir": "up" if up else "down"}
        unit = " pts" if as_points else "%"
        return {"text": f"{abs(diff):.1f}{unit}", "tone": "good" if good else "bad", "dir": "up" if up else "down"}

    return {
        "cur": cur, "prev": prev, "series": s,
        "sent": {"value": cur["sent"], "delta": change("sent", True, False, neutral=True), "spark": s["send"]},
        "delivered": {"value": cur["delivered_rate"], "delta": change("delivered_rate", True, True), "spark": s["delivery"]},
        "bounce": {"value": cur["bounce_rate"], "delta": change("bounce_rate", False, True), "spark": s["bounce"]},
        "complaint": {"value": cur["complaint_rate"], "delta": change("complaint_rate", False, True), "spark": s["complaint"]},
    }


def spark_points(values, width=84, height=26):
    """SVG polyline points string for a tiny sparkline (no JS needed)."""
    if len(values) < 2:
        return ""
    hi = max(values) or 1
    step = width / (len(values) - 1)
    return " ".join(f"{i * step:.1f},{height - 2 - (v / hi) * (height - 4):.1f}" for i, v in enumerate(values))


# ---------------------------------------------------------------- by recipient provider
# Big mailbox providers judge your mail on their own terms, so a problem often shows up at one of them first.
# Only the consumer domains are named; a company on Google Workspace or Microsoft 365 has its own domain and lands in
# "Other domains" (finding out who hosts a domain needs a DNS lookup per domain, which a dashboard should not do).
PROVIDERS = (
    ("Gmail", re.compile(r"^(gmail|googlemail)\.com$")),
    ("Microsoft", re.compile(r"^(outlook|hotmail|live|msn)\.[a-z.]+$")),
    ("Yahoo and AOL", re.compile(r"^((yahoo|ymail|rocketmail)\.[a-z.]+|aol\.com)$")),
    ("Apple", re.compile(r"^(icloud|me|mac)\.com$")),
    ("Proton", re.compile(r"^(proton\.me|protonmail\.com|pm\.me)$")),
)
OTHER_PROVIDER = "Other domains"
TONE_MIN_SAMPLE = 20  # a rate from fewer mails than this is shown but never coloured: 1 bounce in 3 is not a trend


def provider_of(domain):
    d = (domain or "").lower()
    return next((name for name, rx in PROVIDERS if rx.match(d)), OTHER_PROVIDER)


def _row(name, n, delivered, bounced, complained):
    th = settings.ALERT_THRESHOLDS

    def tone(rate, warn, page):
        return "" if n < TONE_MIN_SAMPLE else "err" if rate >= page else "warn" if rate >= warn else ""
    br, cr = (bounced / n if n else 0.0), (complained / n if n else 0.0)
    return {"name": name, "sent": n, "delivered": delivered, "bounced": bounced, "complained": complained,
            "delivered_rate": delivered / n if n else 0.0, "bounce_rate": br, "complaint_rate": cr,
            "bounce_tone": tone(br, th["bounce_warn"], th["bounce_page"]), "complaint_tone": tone(cr, th["complaint_warn"], th["complaint_page"])}


def by_provider(hours=24, now=None, scope_domains=None, top=5):
    """Recipients grouped by provider, plus the recipient domains with the most problems.

    Counts recipients (one mail to two people is two), by their latest state, for mail sent in the window. A user scoped
    to some From-domains only sees mail from those domains, as on the message list.
    """
    now = now or timezone.now()
    qs = MessageRecipient.objects.filter(message__sent_at__gte=now - timedelta(hours=hours))
    if scope_domains:
        qs = qs.filter(message__from_domain__in=[d.lower() for d in scope_domains])
    domain = Substr("address_lower", StrIndex("address_lower", Value("@")) + 1)
    rows = qs.annotate(domain=domain).values("domain").annotate(
        n=Count("id"), delivered=Count("id", filter=Q(state="delivery")),
        bounced=Count("id", filter=Q(state="bounce")), complained=Count("id", filter=Q(state="complaint")))
    totals, domains = {}, []
    for r in rows:
        name = provider_of(r["domain"])
        t = totals.setdefault(name, [0, 0, 0, 0])
        for i, k in enumerate(("n", "delivered", "bounced", "complained")):
            t[i] += r[k]
        if r["bounced"] or r["complained"]:
            domains.append({**_row(r["domain"], r["n"], r["delivered"], r["bounced"], r["complained"]), "provider": name})
    order = [name for name, _ in PROVIDERS] + [OTHER_PROVIDER]
    providers = sorted((_row(name, *t) for name, t in totals.items()), key=lambda x: (-x["sent"], order.index(x["name"])))
    domains.sort(key=lambda d: (-(d["bounced"] + d["complained"]), -d["sent"], d["name"]))
    return {"providers": providers, "domains": domains[:top]}


# ---------------------------------------------------------------- spend estimate
def cost_by_app(since, now=None, scope_domains=None, top=8):
    """An ESTIMATE of SES message charges from `since`: every recipient is one billable email at SES_PRICE_PER_1000.

    Not included, because the console cannot know them: data charges for attachments, any free tier, Virtual Deliverability
    Manager, dedicated IPs, and mail sent outside the console's view. Returns the total and the busiest apps.
    """
    now = now or timezone.now()
    qs = MessageRecipient.objects.filter(message__sent_at__gte=since, message__sent_at__lte=now)
    if scope_domains:
        qs = qs.filter(message__from_domain__in=[d.lower() for d in scope_domains])
    rows = qs.values("message__source_app").annotate(n=Count("id")).order_by("-n")
    price = settings.SES_PRICE_PER_1000 / 1000
    apps, total = [], 0
    for r in rows:
        apps.append({"app": r["message__source_app"] or "(untagged)", "recipients": r["n"], "cost": r["n"] * price})
        total += r["n"]
    return {"recipients": total, "cost": total * price, "apps": apps[:top], "more": max(len(apps) - top, 0)}


def month_start(now=None):
    now = now or timezone.now()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
