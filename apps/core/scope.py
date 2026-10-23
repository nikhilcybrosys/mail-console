"""Per-user visibility rules (the From-domain scope) shared by the pages that would otherwise show other domains' details."""


def scoped_identities(user, rows):
    """Keep only the identities a scoped user may see. A user with no scope sees all. An address identity
    (a@example.com) is visible when its own name or its domain is in scope."""
    if user is None or not user.scope_domains:
        return rows
    allowed = {d.lower() for d in user.scope_domains}
    return [r for r in rows if r.identity.lower() in allowed or r.identity.lower().split("@")[-1] in allowed]


# Alerts are keyed by what they are about. A scoped user sees the account-level ones (no domain or app is named) and the DNS
# alerts of their own domains. Per-app alerts name apps we cannot tie to a domain, and any key we do not recognise is hidden:
# deny by default, so a new kind of alert cannot leak until someone decides it may be shown.
_ACCOUNT_KEYS = {"bounce_rate", "complaint_rate"}
_ACCOUNT_PREFIXES = ("enforcement:", "sending_disabled:", "quota:", "silent:")


def scoped_alerts(user, qs):
    if user is None or not user.scope_domains:
        return qs
    allowed = {d.lower() for d in user.scope_domains}
    keep = []
    for pk, key in qs.values_list("pk", "key"):
        if key.startswith("dns:"):
            parts = key.split(":")
            ok = len(parts) > 2 and parts[1].lower() in allowed
        else:
            ok = key in _ACCOUNT_KEYS or key.startswith(_ACCOUNT_PREFIXES)
        if ok:
            keep.append(pk)
    return qs.filter(pk__in=keep)


def scoped_suppression(user, qs):
    """A suppression entry is account-wide. A scoped user sees only addresses that mail from their own domains was sent to."""
    if user is None or not user.scope_domains:
        return qs
    from apps.sesdata.models import MessageRecipient
    mine = MessageRecipient.objects.filter(message__from_domain__in=[d.lower() for d in user.scope_domains]).values("address_lower")
    return qs.filter(address_lower__in=mine)


def scoped_suppression_changes(user, qs):
    if user is None or not user.scope_domains:
        return qs
    from django.db.models.functions import Lower
    from apps.sesdata.models import MessageRecipient
    mine = MessageRecipient.objects.filter(message__from_domain__in=[d.lower() for d in user.scope_domains]).values("address_lower")
    return qs.annotate(addr_l=Lower("address")).filter(addr_l__in=mine)
