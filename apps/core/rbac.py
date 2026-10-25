"""Role-based access control.

Roles are cumulative in capability but explicit in code: every view/action names the
capability it needs, and the matrix below is the single source of truth (and is tested).
"""
from functools import wraps

from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

VIEWER = "viewer"
SUPPORT = "support"
DELIVERABILITY_ADMIN = "deliverability_admin"
SECURITY_ADMIN = "security_admin"
ROLES = [VIEWER, SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN]

# capability -> roles allowed
CAPABILITIES = {
    "view_metadata": {VIEWER, SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "view_audit": {SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "reveal_body": {SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "view_inbound": {SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "suppression_remove_single": {SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "suppression_bulk": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "template_write": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "identity_write": {SECURITY_ADMIN},
    "event_destination_write": {SECURITY_ADMIN},
    "account_attrs_write": {SECURITY_ADMIN},
    "view_setup": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "test_alert_channels": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "export_data": {SUPPORT, DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "compose_send": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "reveal_sent_body": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "manage_senders": {SECURITY_ADMIN},
    "dmarc_upload": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "manage_templates": {SECURITY_ADMIN},
    "manage_users": {SECURITY_ADMIN},
    "approve": {DELIVERABILITY_ADMIN, SECURITY_ADMIN},
    "break_glass": {SECURITY_ADMIN},
}


def has_capability(user, capability):
    if not user.is_authenticated or not user.is_active:
        return False
    allowed = CAPABILITIES.get(capability)
    if allowed is None:
        raise KeyError(f"Unknown capability {capability!r}")  # fail loud on typos
    return user.effective_role in allowed


def require_capability(capability, *, step_up=False):
    """View decorator. `step_up=True` additionally demands a fresh passkey assertion."""

    def deco(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(f"/login/?next={request.path}")
            if not has_capability(request.user, capability):
                raise PermissionDenied
            if step_up and not request.user.has_fresh_step_up(request.session):
                from urllib.parse import urlencode

                from django.http import HttpResponseRedirect
                from django.urls import reverse
                # Encoded: an unencoded "?a=1&b=2" would put b into the step-up URL's own query and drop it from `next`,
                # so after the passkey the person would land on a wider page (or export) than the one they asked for.
                return HttpResponseRedirect(f"{reverse('step_up')}?{urlencode({'next': request.get_full_path()})}")
            return view(request, *args, **kwargs)

        return wrapper

    return deco
