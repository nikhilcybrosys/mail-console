"""Small, safe template helpers: icons, status badges, relative times, number formats, sort links."""
import re
from datetime import timezone as dt_tz
from urllib.parse import urlencode

from django import template
from django.templatetags.static import static
from django.utils import timezone
from django.utils.html import format_html

register = template.Library()
_NAME = re.compile(r"^[a-z0-9-]+$")  # icon names are developer-supplied; validated so the href can never be abused


@register.simple_tag
def icon(name, cls=""):
    if not _NAME.match(name):
        return ""
    return format_html('<svg class="icon {}" aria-hidden="true"><use href="{}#i-{}"></use></svg>', cls, static("icons/sprite.svg"), name)


# SES event/state -> (badge tone, label, timeline icon)
STATES = {
    "send": ("info", "Sent", "send"), "delivery": ("ok", "Delivered", "circle-check"), "bounce": ("err", "Bounced", "mail-x"),
    "complaint": ("err", "Complaint", "shield-alert"), "deliverydelay": ("warn", "Delayed", "clock"), "reject": ("err", "Rejected", "ban"),
    "renderingfailure": ("err", "Render failed", "triangle-alert"), "open": ("tag", "Opened", "eye"), "click": ("tag", "Clicked", "external-link"),
    "subscription": ("tag", "Subscription", "mail-check"),
}


@register.simple_tag
def state_badge(state):
    tone, label, _ = STATES.get(state, ("plain", state or "Unknown", "circle"))
    return format_html('<span class="badge badge-{}">{}</span>', tone, label)


@register.filter
def state_tone(state):
    return STATES.get(state, ("plain",))[0]


@register.filter
def state_label(state):
    return STATES.get(state, ("", state or "Unknown"))[1]


@register.filter
def state_icon(state):
    return STATES.get(state, ("", "", "circle"))[2]


def _span(secs):
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


@register.simple_tag
def ago(dt):
    """<time> with a relative label ("5m ago" or, for future times, "in 23h") and the exact UTC time in the tooltip."""
    if not dt:
        return "-"
    secs = int((timezone.now() - dt).total_seconds())
    if secs < -5:
        label = f"in {_span(-secs)}"
    elif secs < 5:
        label = "just now"
    elif secs >= 86400 * 30:
        label = dt.astimezone(dt_tz.utc).strftime("%d %b %Y")
    else:
        label = f"{_span(secs)} ago"
    return format_html('<time datetime="{}" title="{}">{}</time>', dt.isoformat(), dt.astimezone(dt_tz.utc).strftime("%d %b %Y %H:%M:%S UTC"), label)


@register.filter
def compact(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return n
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if abs(n) >= div:
            return f"{n / div:.1f}".rstrip("0").rstrip(".") + suf
    return f"{n:.0f}"


@register.filter
def usd(value):
    """US dollars for an ESTIMATE: tiny amounts keep four decimals so they do not all read as $0.00."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "-"
    if v == 0:
        return "$0.00"
    return f"${v:.4f}" if v < 0.01 else f"${v:,.2f}"


@register.filter
def pct(fraction, digits=2):
    try:
        return f"{float(fraction) * 100:.{int(digits)}f}%"
    except (TypeError, ValueError):
        return "-"


@register.simple_tag(takes_context=True)
def sort_link(context, label, field, target="#results"):
    """Header link that toggles sort direction and preserves the other filters (HTMX + normal href)."""
    req = context["request"]
    cur, direction = req.GET.get("sort", ""), req.GET.get("dir", "desc")
    nxt = "asc" if cur == field and direction == "desc" else "desc"
    q = req.GET.copy()
    q["sort"], q["dir"] = field, nxt
    q.pop("page", None)
    state = "ascending" if cur == field and direction == "asc" else "descending" if cur == field else "none"
    glyph = "arrow-up" if state == "ascending" else "arrow-down" if state == "descending" else "arrow-up-down"
    url = f"{req.path}?{urlencode(q, doseq=True)}"
    return format_html('<a class="sort" href="{}" hx-get="{}" hx-target="{}" hx-push-url="true">{}{}</a>', url, url, target, label, icon(glyph))


@register.simple_tag(takes_context=True)
def sort_state(context, field):
    """Value for aria-sort on the column header (the attribute is only valid on <th>, not on the link)."""
    req = context["request"]
    if req.GET.get("sort") != field:
        return "none"
    return "ascending" if req.GET.get("dir") == "asc" else "descending"


@register.simple_tag(takes_context=True)
def qs_without(context, *keys):
    """Current query string minus some keys (used for removable filter chips)."""
    q = context["request"].GET.copy()
    for k in keys:
        q.pop(k, None)
    q.pop("page", None)
    enc = urlencode(q, doseq=True)
    return f"{context['request'].path}?{enc}" if enc else context["request"].path


@register.simple_tag
def meter(percent, tone="ok"):
    """Horizontal meter as inline SVG (percent attributes are not blocked by the CSP, `style=` would be)."""
    try:
        p = max(0.0, min(100.0, float(percent)))
    except (TypeError, ValueError):
        p = 0.0
    tone = tone if tone in ("ok", "warn", "err", "info") else "ok"
    return format_html('<svg class="meter meter-{}" viewBox="0 0 100 6" preserveAspectRatio="none" role="img" aria-label="{}%">'
                       '<rect class="track" width="100" height="6" rx="3"/><rect class="fill" width="{}" height="6" rx="3"/></svg>', tone, f"{p:.0f}", f"{p:.1f}")


@register.simple_tag(takes_context=True)
def qs_with(context, **kwargs):
    """Current path + query string with some keys replaced (pagination links)."""
    q = context["request"].GET.copy()
    for k, v in kwargs.items():
        q[k] = v
    return f"{context['request'].path}?{urlencode(q, doseq=True)}"


# ---- Phase B helpers -----------------------------------------------------------------------------
DNS_LABELS = {"dkim": "DKIM", "spf": "SPF", "dmarc": "DMARC", "mail_from_mx": "MAIL FROM (MX)", "mail_from_spf": "MAIL FROM (SPF)"}
ACTION_LABELS = {
    "suppression.remove": "Remove from suppression list", "suppression.add": "Add to suppression list", "identity.delete": "Delete sending identity",
    "identity.dkim": "Change DKIM signing", "identity.mail_from": "Change MAIL FROM domain", "account.sending": "Pause or resume account sending",
    "account.suppression": "Change account suppression settings", "event_destination.change": "Change an event destination",
}
APPROVAL_TONES = {"pending": "info", "approved": "info", "executing": "info", "executed": "ok", "failed": "err", "rejected": "warn", "expired": "plain"}


@register.filter
def dns_label(kind):
    return DNS_LABELS.get(kind, kind)


@register.filter
def action_label(action):
    return ACTION_LABELS.get(action, action)


@register.filter
def approval_tone(state):
    return APPROVAL_TONES.get(state, "plain")


@register.filter
def json_pretty(value):
    import json
    try:
        return json.dumps(value, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def params_brief(params):
    """One readable line describing an approval request's parameters (plain text; autoescaped by the template)."""
    if not isinstance(params, dict):
        return ""
    if "addresses" in params:
        a = params["addresses"]
        shown = ", ".join(a[:4]) + (f" and {len(a) - 4} more" if len(a) > 4 else "")
        return f"{len(a)} address{'es' if len(a) != 1 else ''}: {shown}"
    return "; ".join(f"{k}: {v}" for k, v in params.items() if not isinstance(v, (dict, list)))[:300]
