from django.conf import settings
from django.urls import reverse

from .rbac import has_capability


def _nav(request, u):
    """Navigation model, filtered by capability. Counts are cheap indexed queries."""
    from apps.approvals.models import ApprovalRequest
    from apps.sesdata.models import Alert

    name = getattr(getattr(request, "resolver_match", None), "url_name", "") or ""
    def item(url_name, label, icon, match=(), count=0):
        m = {url_name, *match}
        return {"url": reverse(url_name), "label": label, "icon": icon, "active": name in m, "count": count}

    from .scope import scoped_alerts
    open_alerts = scoped_alerts(u, Alert.objects.filter(resolved_at__isnull=True)).count()
    groups = [{"label": "Monitor", "items": [
        item("dashboard", "Overview", "layout-dashboard"),
        item("messages", "Sent mail", "mail", ("message_detail",)),
        item("suppression", "Suppression", "ban"),
        item("identities", "Domains and DNS", "globe"),
        item("config_sets", "Event pipeline", "activity"),
        item("alerts", "Alerts", "bell", count=open_alerts),
    ]}]
    if has_capability(u, "view_inbound"):
        groups.append({"label": "Inbound", "items": [
            item("inbox", "Inbox", "inbox", ("inbound_detail",)), item("dmarc", "DMARC reports", "shield-check")]})
    if settings.SEND_ENABLED and has_capability(u, "compose_send"):
        groups.append({"label": "Send", "items": [item("compose", "Compose", "send", ("compose_new", "compose_edit", "compose_preview", "compose_senders"))]})
    gov = []
    if has_capability(u, "approve"):
        gov.append(item("approvals", "Approvals", "shield-check", count=ApprovalRequest.objects.filter(state="pending").count()))
    if has_capability(u, "view_audit"):
        gov.append(item("audit", "Audit log", "scroll-text"))
    if has_capability(u, "manage_users"):
        gov.append(item("users", "Users and roles", "users"))
    if has_capability(u, "view_setup"):
        gov.append(item("setup_check", "Setup check", "circle-check"))
    if gov:
        groups.append({"label": "Governance", "items": gov})
    return groups


def console_context(request):
    u = getattr(request, "user", None)
    authed = bool(u and u.is_authenticated)
    ctx = {
        "brand_name": settings.BRAND_NAME, "brand_logo": settings.BRAND_LOGO, "brand_logo_dark": settings.BRAND_LOGO_DARK,
        "oidc_provider": settings.OIDC_PROVIDER_NAME, "csp_nonce": getattr(request, "csp_nonce", ""),
        "aws_regions": settings.AWS_REGIONS,
        "current_region": request.session.get("region", settings.AWS_REGIONS[0]) if hasattr(request, "session") else settings.AWS_REGIONS[0],
        "can_approve": authed and has_capability(u, "approve"), "can_audit": authed and has_capability(u, "view_audit"),
        "can_manage_users": authed and has_capability(u, "manage_users"),
    }
    if authed:
        ctx["nav_groups"] = _nav(request, u)
        ctx["user_initials"] = "".join(p[0] for p in (u.name or u.email.split("@")[0]).replace(".", " ").split()[:2]).upper() or "?"
    return ctx
