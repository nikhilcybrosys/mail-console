"""Console views. Every view names the capability it needs; step-up is demanded for writes and reveals."""
import re
from datetime import timedelta

import requests

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.cache import patch_vary_headers
from urllib.parse import urlencode
from django.views.decorators.http import require_POST

from apps.accounts.models import User
from apps.approvals import service as approvals
from apps.approvals.models import ApprovalRequest
from apps.audit.models import AuditLog
from apps.audit.service import record, verify_chain
from apps.core.rbac import ROLES, has_capability, require_capability
from apps.core.scope import scoped_identities
from apps.core.templatetags.ui import STATES
from apps.sesdata import channels, metrics, setupcheck, sync
from apps.sesdata.events import SUPPRESSION_SUBTYPES  # noqa: F401  (re-exported for templates/tests)
from apps.sesdata.explain import explain
from apps.sesdata.models import (AccountSnapshot, Alert, BodyAccessLog, ConfigSetSnapshot, DnsCheckResult, IdentitySnapshot,
                                 MailCategory, Message, MessageRecipient, SuppressionChange, SuppressionEntry)

_MSG_ID = re.compile(r"^[0-9a-zA-Z-]{12,}$")
PAGE = 50


def _region(request):
    r = request.session.get("region")
    return r if r in settings.AWS_REGIONS else settings.AWS_REGIONS[0]


def _scoped(qs, user, field="from_domain"):
    """Restrict to the user's allowed From-domains (empty scope = all)."""
    if user.scope_domains:
        return qs.filter(**{f"{field}__in": [d.lower() for d in user.scope_domains]})
    return qs


def _page(request, qs):
    return Paginator(qs, PAGE).get_page(request.GET.get("page"))


@require_POST
@require_capability("view_metadata")
def set_region(request):
    r = request.POST.get("region", "")
    if r in settings.AWS_REGIONS:
        request.session["region"] = r
    return redirect(request.POST.get("next") if (request.POST.get("next") or "").startswith("/") and not (request.POST.get("next") or "").startswith("//") else "/")


# ------------------------------------------------------------------ helpers
WINDOWS = {"24h": 24, "7d": 168, "30d": 720}


def _is_fragment(request):
    """True when HTMX asked for just the results region (so the same URL also works as a full page)."""
    return request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") in ("results", "drawer-body", "palette-results")


def _vary(resp):
    patch_vary_headers(resp, ["HX-Request", "HX-Target"])
    return resp


# ------------------------------------------------------------------ dashboard
@require_capability("view_metadata")
def dashboard(request):
    region = _region(request)
    win = request.GET.get("window", "24h")
    hours = WINDOWS.get(win, 24)
    win = win if win in WINDOWS else "24h"
    k = metrics.kpis(hours)
    s = k["series"]
    chart = {"x": s["x"], "series": [
        {"key": "send", "label": "Sent", "color": "--chart-2", "values": s["send"]},
        {"key": "delivery", "label": "Delivered", "color": "--chart-3", "values": s["delivery"]},
        {"key": "bounce", "label": "Bounced", "color": "--chart-1", "values": s["bounce"]},
        {"key": "complaint", "label": "Complaints", "color": "--chart-4", "values": s["complaint"]}]}
    tiles = [
        {"label": "Emails sent", "value": k["sent"]["value"], "kind": "count", "delta": k["sent"]["delta"], "spark": metrics.spark_points(k["sent"]["spark"])},
        {"label": "Delivered", "value": k["delivered"]["value"], "kind": "pct", "delta": k["delivered"]["delta"], "spark": metrics.spark_points(k["delivered"]["spark"])},
        {"label": "Bounce rate", "value": k["bounce"]["value"], "kind": "pct", "delta": k["bounce"]["delta"], "spark": metrics.spark_points(k["bounce"]["spark"])},
        {"label": "Complaint rate", "value": k["complaint"]["value"], "kind": "pct3", "delta": k["complaint"]["delta"], "spark": metrics.spark_points(k["complaint"]["spark"])},
    ]
    snap = AccountSnapshot.objects.filter(region=region).order_by("-taken_at").first()
    rep, th = metrics.reputation_estimate(hours), settings.ALERT_THRESHOLDS

    def tone(rate, warn, page):
        return "err" if rate >= page else "warn" if rate >= warn else "ok"
    meters = [
        {"label": "Bounce rate", "rate": rep["bounce_rate"], "review": 0.05, "tone": tone(rep["bounce_rate"], th["bounce_warn"], th["bounce_page"]), "digits": 2},
        {"label": "Complaint rate", "rate": rep["complaint_rate"], "review": 0.001, "tone": tone(rep["complaint_rate"], th["complaint_warn"], th["complaint_page"]), "digits": 3},
    ]
    for m in meters:
        m["fill"] = round(min(100.0, m["rate"] / m["review"] * 100), 1)
    reasons = metrics.top_bounce_reasons(hours)
    top = max([r["count"] for r in reasons] or [1])
    for r in reasons:
        r["fill"] = round(r["count"] / top * 100, 1)
    attention = []
    for a in Alert.objects.filter(resolved_at__isnull=True).order_by("-opened_at")[:4]:
        attention.append({"tone": "err" if a.severity == "page" else "warn", "icon": "triangle-alert", "text": a.title, "url": reverse("alerts"), "cta": "Review"})
    if has_capability(request.user, "approve"):
        n = ApprovalRequest.objects.filter(state=ApprovalRequest.PENDING).count()
        if n:
            attention.append({"tone": "info", "icon": "shield-check", "text": f"{n} approval{'s' if n != 1 else ''} waiting for review", "url": reverse("approvals"), "cta": "Open queue"})
    return render(request, "console/dashboard.html", {
        "snap": snap, "window": win, "tiles": tiles, "chart": chart, "meters": meters, "reasons": reasons, "apps": metrics.by_app(hours),
        "recipients": metrics.by_provider(hours, scope_domains=request.user.scope_domains),
        "attention": attention, "quota_pct": round(100 * snap.sent_last_24h / snap.max_24h_send, 1) if snap and snap.max_24h_send else 0,
        "sample": rep["sample"], "last_event": max([v for v in metrics.last_event_by_config_set().values() if v] or [None]) if Message.objects.exists() else None,
    })


# ------------------------------------------------------------------ search / messages
@require_capability("view_metadata")
def global_search(request):
    """Enter in the search box: jump straight to a message, an address, or a domain."""
    q = (request.GET.get("q") or "").strip()
    if not q:
        return redirect("messages")
    if "@" in q:
        return redirect(f"/messages/?{urlencode({'q': q})}")
    if _MSG_ID.match(q):
        m = _scoped(Message.objects.filter(ses_message_id__startswith=q), request.user).first()
        if m:
            return redirect(f"/messages/?open={m.pk}")
    if "." in q and " " not in q:
        return redirect(f"/messages/?{urlencode({'domain': q})}")
    return redirect(f"/messages/?{urlencode({'q': q})}")


@require_capability("view_metadata")
def palette(request):
    """Command-palette results fragment. Same scope and capability rules as the full pages."""
    q = (request.GET.get("q") or "").strip()[:120]
    groups = []
    pages = [("Overview", "/", "layout-dashboard"), ("Sent mail", "/messages/", "mail"), ("Suppression list", "/suppression/", "ban"),
             ("Domains and DNS", "/identities/", "globe"), ("Event pipeline", "/config-sets/", "activity"), ("Alerts", "/alerts/", "bell")]
    if has_capability(request.user, "view_inbound"):
        pages.append(("Inbox", "/inbox/", "inbox"))
    if has_capability(request.user, "view_audit"):
        pages.append(("Audit log", "/audit/", "scroll-text"))
    if q:
        pages = [p for p in pages if q.lower() in p[0].lower()]
        if "@" in q:
            rows = MessageRecipient.objects.filter(address_lower__startswith=q.lower(), message__in=_scoped(Message.objects.all(), request.user)) \
                .values_list("address", flat=True).distinct()[:5]
            groups.append(("Recipients", [(a, f"/messages/?{urlencode({'q': a})}", "mail") for a in rows] +
                           [(f"Check suppression for {q}", f"/suppression/?{urlencode({'q': q})}", "ban")]))
        elif _MSG_ID.match(q):
            ms = _scoped(Message.objects.filter(ses_message_id__startswith=q), request.user)[:5]
            groups.append(("Messages", [(f"{m.ses_message_id} · {m.subject or 'no subject'}", f"/messages/?open={m.pk}", "mail") for m in ms]))
        if "." in q and " " not in q and "@" not in q:
            groups.append(("Domains", [(f"Mail from {q}", f"/messages/?{urlencode({'domain': q})}", "globe")]))
        groups.append(("Search", [(f"Subjects containing “{q}”", f"/messages/?{urlencode({'q': q})}", "search")]))
    groups.insert(0, ("Go to", pages)) if pages else None
    resp = render(request, "console/_palette_results.html", {"groups": [(t, i) for t, i in groups if i], "q": q})
    return _vary(resp)


SORTS = {"sent_at": "sent_at", "subject": "subject", "state": "final_state", "app": "source_app"}
FILTERS = (("state", "final_state", "Status"), ("app", "source_app", "App"), ("config_set", "config_set", "Config set"),
           ("domain", "from_domain", "Domain"), ("category", "mail_category", "Category"))
STATE_TABS = [("", "All"), ("delivery", "Delivered"), ("bounce", "Bounced"), ("deliverydelay", "Delayed"), ("complaint", "Complaints"), ("send", "In flight")]


def _filtered_messages(request, skip=()):
    qs = _scoped(Message.objects.all(), request.user)
    q = (request.GET.get("q") or "").strip()
    if q and "q" not in skip:
        if "@" in q:
            qs = qs.filter(pk__in=MessageRecipient.objects.filter(address_lower__startswith=q.lower()).values("message_id"))
        elif _MSG_ID.match(q):
            qs = qs.filter(ses_message_id__startswith=q)
        else:
            qs = qs.filter(subject__icontains=q)
    for param, field, _ in FILTERS:
        v = request.GET.get(param)
        if v and param not in skip:
            qs = qs.filter(**{field: v})
    days = request.GET.get("days")
    if days and days.isdigit() and "days" not in skip:
        qs = qs.filter(sent_at__gte=timezone.now() - timedelta(days=min(int(days), 365)))
    return qs


@require_capability("view_metadata")
def messages_list(request):
    qs = _filtered_messages(request)
    counts = dict(_filtered_messages(request, skip=("state",)).values_list("final_state").annotate(n=Count("id")).values_list("final_state", "n"))
    total_all = sum(counts.values())
    tabs = [{"key": k, "label": label, "count": total_all if not k else counts.get(k, 0), "active": (request.GET.get("state", "") == k)} for k, label in STATE_TABS]
    for t in tabs:
        q = request.GET.copy()
        q.pop("page", None)
        q.pop("state", None)
        if t["key"]:
            q["state"] = t["key"]
        enc = urlencode(q, doseq=True)
        t["url"] = f"{request.path}?{enc}" if enc else request.path
    sort = request.GET.get("sort") if request.GET.get("sort") in SORTS else "sent_at"
    direction = "asc" if request.GET.get("dir") == "asc" else "desc"
    order = (SORTS[sort] if direction == "asc" else "-" + SORTS[sort], "-id")
    page = _page(request, qs.order_by(*order).prefetch_related("recipients"))
    chips = []
    labels = {k: lbl for k, _, lbl in FILTERS}
    for key in ("q", "days") + tuple(k for k, _, _ in FILTERS):
        v = request.GET.get(key)
        if v:
            rest = request.GET.copy()
            rest.pop(key, None)
            rest.pop("page", None)
            enc = urlencode(rest, doseq=True)
            label = {"q": "Search", "days": "Last"}.get(key) or labels.get(key, key)
            value = f"{v}d" if key == "days" else (STATES.get(v, ("", v))[1] if key == "state" else v)  # show "Bounced", not "bounce"
            chips.append({"label": label, "value": value, "url": f"{request.path}?{enc}" if enc else request.path})
    ctx = {"page": page, "tabs": tabs, "chips": chips, "q": request.GET.get("q", ""), "filters": request.GET, "total": qs.count() if page.paginator.num_pages > 1 else page.paginator.count,
           "apps": Message.objects.values_list("source_app", flat=True).distinct().order_by("source_app"),
           "open_id": request.GET.get("open", "")}
    resp = render(request, "console/_messages_results.html" if _is_fragment(request) else "console/messages.html", ctx)
    return _vary(resp)


def _message_context(request, pk):
    msg = get_object_or_404(_scoped(Message.objects.all(), request.user), pk=pk)
    timeline = []
    for e in msg.events.all():
        what, todo = explain(e.event_type, _detail(e))
        timeline.append({"e": e, "what": what, "todo": todo, "detail": _detail(e)})
    recipients = list(msg.recipients.all())
    return {
        "m": msg, "timeline": timeline, "recipients": recipients,
        "can_body": bool(msg.body_ref) and has_capability(request.user, "reveal_body"),
        "category": MailCategory.objects.filter(name=msg.mail_category).first(),
        "suppressed": {s.address_lower: s for s in SuppressionEntry.objects.filter(address_lower__in=[r.address_lower for r in recipients])},
    }


@require_capability("view_metadata")
def message_detail(request, pk):
    return render(request, "console/message_detail.html", _message_context(request, pk))


@require_capability("view_metadata")
def message_drawer(request, pk):
    return _vary(render(request, "console/_message_drawer.html", _message_context(request, pk)))


def _detail(e):
    p = e.payload
    t = e.event_type
    if t == "bounce":
        b = p.get("bounce", {})
        return {"bounceType": b.get("bounceType"), "bounceSubType": b.get("bounceSubType"), "diagnostic": [r.get("diagnosticCode", "") for r in b.get("bouncedRecipients", [])]}
    if t == "complaint":
        return {"complaintFeedbackType": p.get("complaint", {}).get("complaintFeedbackType")}
    if t == "deliverydelay":
        d = p.get("deliveryDelay", {})
        return {"delayType": d.get("delayType"), "expirationTime": d.get("expirationTime")}
    if t == "delivery":
        return {"smtpResponse": p.get("delivery", {}).get("smtpResponse")}
    return {}


@require_POST
@require_capability("reveal_body", step_up=True)
def message_body(request, pk):
    """Issue a short-lived signed URL for the cookie-less mailview origin. Reason is mandatory and audited."""
    from apps.inbound.tokens import issue
    msg = get_object_or_404(_scoped(Message.objects.all(), request.user), pk=pk)
    reason = (request.POST.get("reason") or "").strip()
    if not msg.body_ref or not reason:
        return HttpResponseBadRequest("A stored body and a reason are required")
    BodyAccessLog.objects.create(user_email=request.user.email, message=msg, reason=reason)
    record("body.view", target=f"message#{msg.pk}", request=request, details={"reason": reason[:200], "category": msg.mail_category})
    return render(request, "console/body_frame.html", {"frame_url": issue("msg", msg.pk, request.user.pk), "title": msg.subject})


# ------------------------------------------------------------------ suppression
@require_capability("view_metadata")
def suppression(request):
    q = (request.GET.get("q") or "").strip()
    region = _region(request)
    qs = SuppressionEntry.objects.filter(region=region)
    if q:
        qs = qs.filter(address_lower__startswith=q.lower())
    page = _page(request, qs.order_by("-last_update_time"))
    changes = SuppressionChange.objects.filter(region=region)
    if q:
        changes = changes.filter(address__istartswith=q)
    return render(request, "console/suppression.html", {
        "page": page, "q": q, "changes": changes.order_by("-at")[:20], "total": SuppressionEntry.objects.filter(region=region).count(),
        "can_remove": has_capability(request.user, "suppression_remove_single"),
        "can_bulk": has_capability(request.user, "suppression_bulk"),
    })


@require_POST
@require_capability("suppression_remove_single", step_up=True)
def suppression_remove(request):
    raw = request.POST.get("addresses", "")
    addresses = list(dict.fromkeys(a.strip() for a in re.split(r"[\s,;]+", raw) if a.strip()))  # exact case preserved
    region = _region(request)
    try:
        req = approvals.request_action(request.user, "suppression.remove", {"addresses": addresses}, region, request.POST.get("reason", ""), request=request)
    except approvals.ApprovalError as exc:
        messages.error(request, str(exc))
        return redirect("suppression")
    if req.state == ApprovalRequest.EXECUTED:
        acct = AccountSnapshot.objects.filter(region=region).order_by("-taken_at").first()
        sync.mirror_removed(acct.aws_account_id if acct else "", region, addresses, request.user.email)
        messages.success(request, f"Removed {len(addresses)} address(es) from the SES suppression list.")
    elif req.state == ApprovalRequest.PENDING:
        messages.info(request, "Sent for approval: a second person must approve this bulk change.")
    else:
        messages.error(request, f"Failed: {req.result.get('error', 'unknown error')}")
    return redirect("suppression")


# ------------------------------------------------------------------ identities / config sets
def _latest(model, region, key):
    seen = {}
    for row in model.objects.filter(region=region).order_by("taken_at"):
        seen[getattr(row, key)] = row
    return list(seen.values())


@require_capability("view_metadata")
def identities(request):
    region = _region(request)
    rows = scoped_identities(request.user, _latest(IdentitySnapshot, region, "identity"))
    checks = {}
    for r in DnsCheckResult.objects.order_by("checked_at"):
        checks.setdefault(r.domain, {})[(r.record_kind, tuple(r.expected))] = r
    items = [{"i": i, "checks": sorted(checks.get(i.identity, {}).values(), key=lambda c: (c.record_kind, c.expected))} for i in rows]
    for it in items:
        it["failing"] = sum(1 for c in it["checks"] if not c.ok)
    return render(request, "console/identities.html", {
        "items": items, "failing_total": sum(it["failing"] for it in items), "checks_total": sum(len(it["checks"]) for it in items)})


@require_capability("view_metadata")
def config_sets(request):
    region = _region(request)
    last = metrics.last_event_by_config_set()
    return render(request, "console/config_sets.html", {
        "items": [{"c": c, "last_event": last.get(c.name)} for c in _latest(ConfigSetSnapshot, region, "name")]})


# ------------------------------------------------------------------ alerts / approvals / audit / users
def _alert_rules():
    """The thresholds in force, for display. They come from MC_ALERT_* settings; nothing here edits them."""
    t = settings.ALERT_THRESHOLDS
    pct = lambda v: f"{v * 100:g}%"  # noqa: E731
    quiet = channels.quiet_window()
    return {
        "bounce": f"{pct(t['bounce_warn'])} warning, {pct(t['bounce_page'])} urgent", "complaint": f"{pct(t['complaint_warn'])} warning, {pct(t['complaint_page'])} urgent",
        "quota": f"{pct(t['quota_warn'])} of the daily quota", "min_sample": settings.ALERT_MIN_SAMPLE, "app_min_sample": settings.ALERT_APP_MIN_SAMPLE,
        "silent": f"at least {settings.ALERT_SILENT_MIN_MINUTES} minutes, and {settings.ALERT_SILENT_GAP_FACTOR:g}× the usual gap between sends (at most {settings.ALERT_SILENT_MAX_HOURS:g} hours)",
        "quiet": f"{settings.ALERT_QUIET_HOURS.strip()} ({settings.ALERT_QUIET_TZ}): warnings wait, urgent alerts do not" if quiet else "",
    }


def _alerts_context(request, test_results=None):
    chans = channels.configured()
    return {
        "open": Alert.objects.filter(resolved_at__isnull=True).order_by("-opened_at"),
        "recent": Alert.objects.filter(resolved_at__isnull=False).order_by("-resolved_at")[:20],
        "channels": [channels.LABELS[c] for c in chans], "rules": _alert_rules(), "notify_resolved": settings.ALERT_NOTIFY_RESOLVED,
        "quiet_now": channels.in_quiet_hours(), "can_test_channels": bool(chans) and has_capability(request.user, "test_alert_channels"),
        "test_results": test_results}


@require_capability("view_metadata")
def alerts_view(request):
    return render(request, "console/alerts.html", _alerts_context(request))


@require_POST
@require_capability("test_alert_channels")
def alerts_test_channels(request):
    """Send a clearly-labelled test notice to each configured channel. Audited; carries no real alert data."""
    results = channels.send_test(requests.post)
    record("alerts.test_notification", request=request, details={"results": {c: ok for c, ok, _ in results}})
    return render(request, "console/alerts.html", _alerts_context(request, [
        {"label": channels.LABELS[c], "ok": ok, "reason": why} for c, ok, why in results]))


@require_capability("approve")
def approvals_queue(request):
    return render(request, "console/approvals.html", {
        "pending": ApprovalRequest.objects.filter(state=ApprovalRequest.PENDING).select_related("requested_by").order_by("created_at"),
        "recent": ApprovalRequest.objects.exclude(state=ApprovalRequest.PENDING).select_related("requested_by", "approver").order_by("-created_at")[:25]})


@require_POST
@require_capability("approve", step_up=True)
def approval_decide(request, pk):
    approve = request.POST.get("decision") == "approve"
    try:
        req = approvals.decide(pk, request.user, approve, request=request)
        if approve:
            req = approvals.execute(req, request.user, request=request)
            if req.action == "suppression.remove" and req.state == ApprovalRequest.EXECUTED:
                sync.mirror_removed("", req.region, req.params["addresses"], req.requested_by.email)
        messages.success(request, f"Request {req.state}.")
    except (approvals.ApprovalError, ApprovalRequest.DoesNotExist) as exc:
        messages.error(request, str(exc))
    return redirect("approvals")


@require_capability("view_audit")
def audit_view(request):
    qs = AuditLog.objects.order_by("-id")
    for p, f in (("actor", "actor__icontains"), ("action", "action__startswith"), ("target", "target__icontains")):
        if request.GET.get(p):
            qs = qs.filter(**{f: request.GET[p]})
    ok = None
    if request.GET.get("verify") == "1":
        ok, bad = verify_chain()
        ok = {"ok": ok, "bad_id": bad}
    return render(request, "console/audit.html", {"page": _page(request, qs), "filters": request.GET, "chain": ok})


def _setup_context(request, test_results=None):
    checks = setupcheck.run_checks(_region(request), user=request.user)
    return {
        "groups": setupcheck.grouped(checks), "summary": setupcheck.worst(checks),
        "n_fail": sum(c.status == setupcheck.FAIL for c in checks), "n_warn": sum(c.status == setupcheck.WARN for c in checks),
        "n_ok": sum(c.status in (setupcheck.OK, setupcheck.INFO) for c in checks),
        "can_test_roles": has_capability(request.user, "identity_write")
                          and bool(settings.AWS_WRITE_ROLE_OPS_ARN or settings.AWS_WRITE_ROLE_SECURITY_ARN),
        "test_results": test_results}


@require_capability("view_setup")
def setup_check(request):
    return render(request, "console/setup.html", _setup_context(request))


@require_POST
@require_capability("identity_write", step_up=True)
def setup_test_write_roles(request):
    """Assume each write role once, as the requesting person, and report. Changes nothing in AWS; audited."""
    results = setupcheck.try_write_roles(_region(request), request.user.email, f"setup-{request.user.pk}-{int(timezone.now().timestamp())}")
    record("setup.test_write_roles", request=request, details={"region": _region(request), "results": {c.key: c.status for c in results}})
    return render(request, "console/setup.html", _setup_context(request, results))


@require_capability("manage_users")
def users_view(request):
    return render(request, "console/users.html", {"users": User.objects.order_by("email"), "roles": ROLES})


@require_POST
@require_capability("manage_users", step_up=True)
def user_update(request, pk):
    target = get_object_or_404(User, pk=pk)
    role, active = request.POST.get("role"), request.POST.get("active") == "1"
    if role not in ROLES:
        return HttpResponseBadRequest("bad role")
    if target.pk == request.user.pk and (role != target.role or not active):
        messages.error(request, "You cannot change your own role or deactivate yourself.")
        return redirect("users")
    # Never leave the system without a security admin.
    if target.role == "security_admin" and (role != "security_admin" or not active):
        if User.objects.filter(role="security_admin", is_active=True).exclude(pk=target.pk).count() == 0:
            messages.error(request, "At least one active security_admin is required.")
            return redirect("users")
    old = (target.role, target.is_active)
    target.role, target.is_active = role, active
    target.save(update_fields=["role", "is_active"])
    if old != (role, active):
        request.session.modified = True
    record("user.updated", request=request, target=target.email, details={"from": {"role": old[0], "active": old[1]}, "to": {"role": role, "active": active}})
    messages.success(request, f"Updated {target.email}.")
    return redirect("users")


def home_redirect(request):
    return redirect("dashboard")
