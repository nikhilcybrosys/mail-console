"""Per-user visibility rules shared by every page that lists SES identities."""


def scoped_identities(user, rows):
    """Keep only the identities a scoped user may see. A user with no scope sees all. An address identity
    (a@example.com) is visible when its own name or its domain is in scope."""
    if user is None or not user.scope_domains:
        return rows
    allowed = {d.lower() for d in user.scope_domains}
    return [r for r in rows if r.identity.lower() in allowed or r.identity.lower().split("@")[-1] in allowed]
