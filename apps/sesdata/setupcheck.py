"""Setup check: is the console wired up end to end, and if not, what exactly is missing?

Most checks read what the 5-minute sync already stored (so the page is fast and makes almost no AWS calls); the only
live AWS call is one read of the event queue's attributes. Nothing here changes anything in AWS, except the explicit
"test write roles" action, which assumes each write role once and does nothing with it.
"""
import re
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.core.scope import scoped_identities

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
_ORDER = {OK: 0, INFO: 0, WARN: 1, FAIL: 2}
SYNC_STALE = timedelta(minutes=15)
# Without these, the console cannot show what happened to a message.
ESSENTIAL_EVENTS = {"SEND", "DELIVERY", "BOUNCE", "COMPLAINT"}


@dataclass
class Check:
    group: str
    key: str
    title: str
    status: str
    detail: str = ""
    fix: str = ""


def worst(checks):
    return max((c.status for c in checks), key=lambda s: _ORDER[s], default=OK)


def _latest(model, region, key):
    seen = {}
    for row in model.objects.filter(region=region).order_by("taken_at"):
        seen[getattr(row, key)] = row
    return list(seen.values())


def _minutes(td):
    m = max(int(td.total_seconds() // 60), 0)
    return "less than a minute" if m < 1 else f"{m} minute{'s' if m != 1 else ''}"


def _short(exc):
    """An AWS error without anything sensitive: the error code, or the exception class."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
    return code or exc.__class__.__name__


# ---------------------------------------------------------------- SES account and identities
def _ses_checks(region, now, user):
    from .models import AccountSnapshot

    g, out = "Amazon SES", []
    snap = AccountSnapshot.objects.filter(region=region).order_by("-taken_at").first()
    if snap is None:
        out.append(Check(g, "sync", "State sync has not run", FAIL,
                         "No SES account state has been read yet, so most pages are empty.",
                         "Start the sync process (python manage.py sync_ses_state) and check that the app role can read SES."))
        return out, []
    age = now - snap.taken_at
    if age > SYNC_STALE:
        out.append(Check(g, "sync", "State sync is behind", WARN, f"Last sync {_minutes(age)} ago; it should run every 5 minutes.",
                         "Check that the sync process is running and look at its log for errors."))
    else:
        out.append(Check(g, "sync", "State sync is running", OK, f"Last sync {_minutes(age)} ago."))

    if snap.production_access:
        out.append(Check(g, "prod", "Production access", OK, "The account can send to any address."))
    else:
        out.append(Check(g, "prod", "Account is in the SES sandbox", WARN, "It can only send to verified addresses.",
                         "Request production access in the SES console."))
    if not snap.sending_enabled:
        out.append(Check(g, "sending", "Sending is paused", FAIL, "SES is not sending any mail from this account in this region.",
                         "Resume sending (needs an approval) if this is not intentional."))
    if snap.enforcement_status and snap.enforcement_status != "HEALTHY":
        out.append(Check(g, "enforce", "SES is enforcing on this account", FAIL, f"Enforcement status: {snap.enforcement_status}.",
                         "Open the SES console for the reason; fix the cause, then ask AWS to lift it."))

    from .models import IdentitySnapshot
    idents = scoped_identities(user, _latest(IdentitySnapshot, region, "identity"))  # same visibility as Domains and DNS
    if not idents:
        out.append(Check(g, "idents", "No sending identities", WARN, "SES has no verified domain or address in this region.",
                         "Verify a domain in the SES console."))
    else:
        bad = [i.identity for i in idents if not i.verified]
        out.append(Check(g, "idents", "Identities verified", WARN if bad else OK,
                         ("Not verified: " + ", ".join(bad)) if bad else f"{len(idents)} identit{'y' if len(idents) == 1 else 'ies'} verified."))
        weak = [i.identity for i in idents if i.identity_type == "DOMAIN" and i.dkim_status != "SUCCESS"]
        if weak:
            out.append(Check(g, "dkim", "DKIM not passing", WARN, "Domains without a passing DKIM check: " + ", ".join(weak),
                             "Publish the three DKIM CNAME records; see Domains and DNS."))
    return out, idents


# ---------------------------------------------------------------- event pipeline
def _destinations(region):
    from .models import ConfigSetSnapshot
    return _latest(ConfigSetSnapshot, region, "name")


def _pipeline_checks(region, idents, now, sqs_client):
    from .models import MessageEvent

    g, out = "Event pipeline", []
    expected = set(settings.EXPECTED_SNS_TOPIC_ARNS)
    sets = _destinations(region)

    # 1. at least one configuration set publishes to a topic this console accepts
    good, wrong_topic, missing_types = [], [], []
    for cs in sets:
        for d in cs.destinations:
            topic = (d.get("SnsDestination") or {}).get("TopicArn")
            if not topic or not d.get("Enabled", False):
                continue
            (good if topic in expected else wrong_topic).append((cs.name, d))
            if topic in expected and not ESSENTIAL_EVENTS <= set(d.get("MatchingEventTypes", [])):
                missing_types.append(cs.name)
    if not expected:
        out.append(Check(g, "topic", "No topic is allowed", FAIL, "MC_EXPECTED_SNS_TOPIC_ARNS is empty, so the worker rejects every event.",
                         "Set MC_EXPECTED_SNS_TOPIC_ARNS to the SNS topic ARN."))
    elif good:
        out.append(Check(g, "dest", "SES publishes events to the console's topic", OK,
                         "Configuration sets: " + ", ".join(sorted({n for n, _ in good})) + "."))
    elif wrong_topic:
        out.append(Check(g, "dest", "SES publishes to a topic the console does not accept", FAIL,
                         "Event destinations exist, but none uses a topic listed in MC_EXPECTED_SNS_TOPIC_ARNS, so the worker would refuse them.",
                         "Point an event destination at the console's topic, or add that topic to MC_EXPECTED_SNS_TOPIC_ARNS."))
    else:
        out.append(Check(g, "dest", "No event destination", FAIL,
                         "No configuration set publishes events to SNS, so SES tells this console nothing.",
                         "Add an SNS event destination to the configuration set your identities use (aws/README.md, step 5)."))
    if missing_types:
        out.append(Check(g, "types", "Event destination misses essential events", WARN,
                         f"{', '.join(sorted(set(missing_types)))} does not send all of SEND, DELIVERY, BOUNCE and COMPLAINT.",
                         "Enable those event types on the event destination."))

    # 2. mail actually goes through a covered configuration set
    covered = {n for n, _ in good}
    uncovered = [i.identity for i in idents if i.default_config_set not in covered]
    if idents and good:
        out.append(Check(g, "cover", "Every identity sends through a covered configuration set", WARN if uncovered else OK,
                         ("No default configuration set (or an uncovered one) on: " + ", ".join(uncovered) +
                          ". Mail from these only produces events if the sender names a covered set.") if uncovered
                         else "Mail from every identity is captured by default."))
        if uncovered:
            out[-1].fix = "Give each identity the covered configuration set as its default (aws/README.md, step 5)."

    # 3. the queue itself (the one live AWS call)
    out.extend(_queue_checks(g, now, sqs_client))

    # 4. evidence that events arrive
    last = MessageEvent.objects.order_by("-received_at").values_list("received_at", flat=True).first()
    if last is None:
        out.append(Check(g, "arrived", "No events received yet", WARN, "Nothing has been ingested.",
                         "Send one email through SES and run this check again. If it stays empty, check the worker log."))
    else:
        age = now - last
        hours = int(age.total_seconds() // 3600)
        out.append(Check(g, "arrived", "Events are arriving", OK if age < timedelta(hours=24) else WARN,
                         f"Last event received {'less than an hour' if hours < 1 else str(hours) + ' hours'} ago."
                         + ("" if age < timedelta(hours=24) else " That is long for an active sender: check that the worker is running.")))
    return out


def _queue_region(url):
    m = re.match(r"https://sqs\.([a-z0-9-]+)\.amazonaws\.com/", url or "")
    return m.group(1) if m else None


def _queue_checks(g, now, sqs_client):
    url = settings.SQS_EVENTS_QUEUE_URL
    if not url:
        return [Check(g, "queue", "No event queue configured", FAIL, "MC_SQS_EVENTS_QUEUE_URL is not set, so the worker cannot start.",
                      "Set MC_SQS_EVENTS_QUEUE_URL to the queue URL.")]
    try:
        if sqs_client is None:
            import boto3
            sqs_client = boto3.client("sqs", region_name=_queue_region(url))
        attrs = sqs_client.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]).get("Attributes", {})
    except Exception as exc:  # noqa: BLE001: reported, not raised; this is a diagnostic page
        return [Check(g, "queue", "Cannot read the event queue", FAIL, f"AWS answered: {_short(exc)}.",
                      "Check the queue URL and that the app role may call sqs:GetQueueAttributes on it.")]
    out = [Check(g, "queue", "Event queue reachable", OK,
                 f"{attrs.get('ApproximateNumberOfMessages', '?')} waiting, {attrs.get('ApproximateNumberOfMessagesNotVisible', '?')} being processed.")]
    try:
        waiting = int(attrs.get("ApproximateNumberOfMessages", 0))
    except ValueError:
        waiting = 0
    if waiting > 1000:
        out[-1].status, out[-1].fix = WARN, "A backlog this large means the worker is not keeping up or is stopped; check its log."
    if "RedrivePolicy" in attrs:
        out.append(Check(g, "dlq", "Dead-letter queue attached", OK, "Messages the worker cannot handle are set aside, not lost."))
    else:
        out.append(Check(g, "dlq", "No dead-letter queue", WARN, "A message the worker cannot process would be retried until it expires.",
                         "Attach a dead-letter queue with a redrive policy (aws/README.md, step 1)."))
    if attrs.get("SqsManagedSseEnabled") == "true" or attrs.get("KmsMasterKeyId"):
        out.append(Check(g, "sse", "Queue is encrypted", OK))
    else:
        out.append(Check(g, "sse", "Queue is not encrypted", WARN, "Event payloads contain recipient addresses.",
                         "Enable server-side encryption on the queue."))
    pol = attrs.get("Policy", "")
    if not pol:
        out.append(Check(g, "qpolicy", "Queue has no access policy", FAIL, "SNS cannot deliver to a queue with no policy.",
                         "Apply the queue policy from aws/policies/sqs-queue-policy.json."))
    else:
        mentions = [t for t in settings.EXPECTED_SNS_TOPIC_ARNS if t in pol]
        if settings.EXPECTED_SNS_TOPIC_ARNS and not mentions:
            out.append(Check(g, "qpolicy", "Queue policy does not name the console's topic", WARN,
                             "Delivery may be refused, or the policy may be broader than intended.",
                             "Re-apply aws/policies/sqs-queue-policy.json with your topic ARN."))
        else:
            out.append(Check(g, "qpolicy", "Queue policy names the topic", OK))
    return out


# ---------------------------------------------------------------- access, sign-in, hardening
def _access_checks(user):
    from apps.accounts.models import User
    from apps.core.rbac import has_capability

    g, out = "Access and sign-in", []
    ops, sec = settings.AWS_WRITE_ROLE_OPS_ARN, settings.AWS_WRITE_ROLE_SECURITY_ARN
    if ops and sec:
        out.append(Check(g, "roles", "Write roles configured", OK, "Approved changes run with the narrow write roles. Use the test below to prove they work."))
    elif ops or sec:
        out.append(Check(g, "roles", "Only one write role configured", WARN, "Some approved changes would fail.",
                         "Set both MC_AWS_WRITE_ROLE_OPS_ARN and MC_AWS_WRITE_ROLE_SECURITY_ARN."))
    else:
        out.append(Check(g, "roles", "Read-only mode", INFO, "No write roles configured: the console shows data but cannot change SES."))

    if settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET:
        out.append(Check(g, "oidc", "Single sign-on configured", OK, f"Provider: {settings.OIDC_PROVIDER_NAME}."))
        out.append(Check(g, "domain", "Sign-in restricted to your organisation", OK if settings.OIDC_ALLOWED_DOMAIN else WARN,
                         f"Only @{settings.OIDC_ALLOWED_DOMAIN} addresses." if settings.OIDC_ALLOWED_DOMAIN
                         else "Any verified address is accepted (people must still be added as users).",
                         "" if settings.OIDC_ALLOWED_DOMAIN else "Set MC_OIDC_ALLOWED_DOMAIN."))
    else:
        out.append(Check(g, "oidc", "Single sign-on is not configured", FAIL if not settings.DEBUG else WARN,
                         "Nobody can sign in except through the development shortcut.", "Set the MC_OIDC_* variables (README, Sign-in)."))

    approvers = [u for u in User.objects.filter(is_active=True) if has_capability(u, "approve")]
    if len(approvers) >= 2:
        out.append(Check(g, "four", "Two or more people can approve changes", OK, f"{len(approvers)} approvers."))
    else:
        out.append(Check(g, "four", "Only one person can approve changes", WARN,
                         "Risky changes need a second person, and nobody can approve their own request.",
                         "Add a second deliverability or security admin under Users and roles."))
    if user is not None and getattr(user, "is_authenticated", False):
        if user.passkeys.exists():
            out.append(Check(g, "passkey", "You have a passkey", OK))
        else:
            out.append(Check(g, "passkey", "You have no passkey yet", WARN, "Changes to SES ask for one.", "Enrol a passkey when prompted."))
    return out


def _hardening_checks():
    g, out = "Hardening", []
    out.append(Check(g, "debug", "Debug mode is off", FAIL if settings.DEBUG else OK,
                     "Debug mode shows internal details and enables a sign-in shortcut." if settings.DEBUG else "",
                     "Set MC_DEBUG=0." if settings.DEBUG else ""))
    weak_key = len(settings.SECRET_KEY) < 50 or "insecure" in settings.SECRET_KEY.lower()
    out.append(Check(g, "key", "Secret key is strong", FAIL if weak_key else OK, "The key is short or a known placeholder." if weak_key else "",
                     "Set MC_SECRET_KEY to a long random string." if weak_key else ""))
    if "*" in settings.ALLOWED_HOSTS:
        out.append(Check(g, "hosts", "Any host name is accepted", FAIL, "ALLOWED_HOSTS contains *.", "List only your console host names."))
    out.append(Check(g, "https", "HTTPS is enforced", OK if (settings.SESSION_COOKIE_SECURE and settings.SECURE_HSTS_SECONDS) else WARN,
                     "Secure cookies and HSTS are on." if (settings.SESSION_COOKIE_SECURE and settings.SECURE_HSTS_SECONDS)
                     else "Cookies or HSTS are not strict.", "" if settings.SESSION_COOKIE_SECURE else "Serve the console over HTTPS only."))
    viewer_off = settings.MAILVIEW_HOST.endswith((".localhost", ".invalid"))
    out.append(Check(g, "viewer", "Mail viewer is off" if viewer_off else "Mail viewer on a separate domain", INFO if viewer_off else OK,
                     "Message bodies and the inbox are unavailable until MC_MAILVIEW_HOST is set to a separate registrable domain."
                     if viewer_off else settings.MAILVIEW_HOST))
    return out


def _compose_checks(region):
    """Only when Compose is switched on: is what it needs in place? (The send role itself is proved by the Test write roles button.)"""
    from apps.compose.models import SenderAddress

    g, out = "Compose", []
    on = list(SenderAddress.objects.filter(enabled=True, address__in=settings.SEND_FROM_ADDRESSES).values_list("address", flat=True))
    if on:
        out.append(Check(g, "senders", "Sending addresses switched on", OK, ", ".join(sorted(on)) + "."))
    else:
        out.append(Check(g, "senders", "No sending address is switched on", WARN, "Nobody can send from Compose yet.", "A security admin turns an address on under Compose, Sending addresses."))
    covered = {c.name for c in _destinations(region) for d in c.destinations
               if d.get("Enabled") and (d.get("SnsDestination") or {}).get("TopicArn") in set(settings.EXPECTED_SNS_TOPIC_ARNS)}
    if settings.SEND_CONFIG_SET in covered:
        out.append(Check(g, "cset", "Compose mail will show up in Sent mail", OK, f"Configuration set {settings.SEND_CONFIG_SET} publishes events to the console."))
    else:
        out.append(Check(g, "cset", "Compose mail would not show up in Sent mail", WARN,
                         f"Configuration set {settings.SEND_CONFIG_SET} was not found with an event destination to the console's topic.",
                         "Check MC_SEND_CONFIG_SET, or add an event destination to it (aws/README.md, step 5)."))
    from .models import IdentitySnapshot
    verified = {i.identity.lower() for i in _latest(IdentitySnapshot, region, "identity") if i.verified}
    missing = [a for a in on if a not in verified and a.split("@")[1] not in verified]
    if missing:
        out.append(Check(g, "ident", "A sending address is not on a verified identity", FAIL, ", ".join(missing),
                         "Verify the domain or address in SES first; SES refuses to send from an unverified identity."))
    return out


def run_checks(region, *, user=None, sqs_client=None, now=None):
    now = now or timezone.now()
    ses, idents = _ses_checks(region, now, user)
    return ses + _pipeline_checks(region, idents, now, sqs_client) + _access_checks(user) + (_compose_checks(region) if settings.SEND_ENABLED else []) + _hardening_checks()


def grouped(checks):
    order, groups = [], {}
    for c in checks:
        if c.group not in groups:
            groups[c.group] = []
            order.append(c.group)
        groups[c.group].append(c)
    return [{"name": n, "checks": groups[n], "status": worst(groups[n])} for n in order]


# ---------------------------------------------------------------- the one active test
def try_write_roles(region, acting_email, request_id, *, assume=None, assume_sender=None):
    """Assume each configured write role once (as the acting person) to prove trust, ExternalId and SourceIdentity work.

    Nothing is changed in AWS; the credentials are discarded. CloudTrail records one AssumeRole per role.
    """
    from . import aws

    assume = assume or aws.assume_writer
    g, out = "Write roles", []
    for tier, setting in aws.TIERS.items():
        if not getattr(settings, setting):
            out.append(Check(g, tier, f"{tier} role not configured", INFO))
            continue
        try:
            assume(region, tier, acting_email, request_id)
        except Exception as exc:  # noqa: BLE001
            out.append(Check(g, tier, f"Cannot assume the {tier} role", FAIL, f"AWS answered: {_short(exc)}.",
                             "The role's trust policy must allow the app role, your e-mail as SourceIdentity, and the ExternalId (aws/policies/trust-write-roles.json)."))
        else:
            out.append(Check(g, tier, f"The {tier} role can be assumed", OK, "Trust policy, ExternalId and your identity were accepted."))
    if settings.SEND_ENABLED:  # Compose's send role: assumed the same way, never used to send from here
        try:
            (assume_sender or aws.assume_sender)(region, acting_email, request_id)
        except Exception as exc:  # noqa: BLE001
            out.append(Check(g, "send", "Cannot assume the send role", FAIL, f"AWS answered: {_short(exc)}.",
                             "Its trust policy must allow the app role, your e-mail as SourceIdentity and the ExternalId (aws/policies/trust-send-role.json), and the app role must be allowed to assume it (aws/policies/app-assume-send.json)."))
        else:
            out.append(Check(g, "send", "The send role can be assumed", OK, "Nothing was sent. Sending still needs a message, a passkey and the limits."))
    return out
