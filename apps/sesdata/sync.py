"""Poll SES control-plane state into snapshot tables (the UI never calls AWS per click)."""
from datetime import timezone as _tz

from django.db import transaction

from .models import AccountSnapshot, ConfigSetSnapshot, IdentitySnapshot, SuppressionChange, SuppressionEntry


def sync_account(reader, account_id, region):
    a = reader.get_account()
    q = a.get("SendQuota", {})
    return AccountSnapshot.objects.create(
        aws_account_id=account_id, region=region, production_access=bool(a.get("ProductionAccessEnabled")),
        sending_enabled=bool(a.get("SendingEnabled")), enforcement_status=a.get("EnforcementStatus", ""),
        max_24h_send=q.get("Max24HourSend", 0), sent_last_24h=q.get("SentLast24Hours", 0), max_send_rate=q.get("MaxSendRate", 0),
        raw={k: v for k, v in a.items() if k != "ResponseMetadata"})


def sync_identities(reader, account_id, region):
    out = []
    for summary in reader.list_identities():
        name = summary["IdentityName"]
        d = reader.get_identity(name)
        dk, mf = d.get("DkimAttributes", {}), d.get("MailFromAttributes", {})
        out.append(IdentitySnapshot.objects.create(
            aws_account_id=account_id, region=region, identity=name, identity_type=d.get("IdentityType", summary.get("IdentityType", "")),
            verified=bool(d.get("VerifiedForSendingStatus")), dkim_status=dk.get("Status", ""), dkim_tokens=dk.get("Tokens", []),
            dkim_signing_origin=dk.get("SigningAttributesOrigin", ""), mail_from_domain=mf.get("MailFromDomain", ""),
            mail_from_status=mf.get("MailFromDomainStatus", ""), default_config_set=d.get("ConfigurationSetName", ""),
            raw={k: v for k, v in d.items() if k not in ("ResponseMetadata", "Policies")}))
    return out


def sync_config_sets(reader, account_id, region):
    out = []
    for name in reader.list_config_sets():
        name = name if isinstance(name, str) else name.get("Name", "")
        cs = reader.get_config_set(name)
        dests = reader.get_event_destinations(name)
        out.append(ConfigSetSnapshot.objects.create(
            aws_account_id=account_id, region=region, name=name, destinations=_jsonable(dests),
            sending_enabled=cs.get("SendingOptions", {}).get("SendingEnabled", True),
            tracking_domain=cs.get("TrackingOptions", {}).get("CustomRedirectDomain", ""),
            archive_arn=cs.get("ArchivingOptions", {}).get("ArchiveArn", ""),
            raw={k: v for k, v in cs.items() if k != "ResponseMetadata"}))
    return out


def _jsonable(obj):
    import json
    return json.loads(json.dumps(obj, default=str))


@transaction.atomic
def sync_suppression(reader, account_id, region):
    """Mirror the account suppression list. Returns (added, removed) counts (seen from the SES side)."""
    remote = {}
    for e in reader.iter_suppressed():
        remote[e["EmailAddress"]] = e
    existing = {s.address: s for s in SuppressionEntry.objects.filter(aws_account_id=account_id, region=region)}
    added = [a for a in remote if a not in existing]
    removed = [a for a in existing if a not in remote]
    for a in added:
        e = remote[a]
        SuppressionEntry.objects.create(
            aws_account_id=account_id, region=region, address=a, address_lower=a.lower(), reason=e.get("Reason", ""),
            last_update_time=e.get("LastUpdateTime"))
        SuppressionChange.objects.create(aws_account_id=account_id, region=region, address=a, change="seen_added", reason=e.get("Reason", ""))
    for a in removed:
        SuppressionChange.objects.create(aws_account_id=account_id, region=region, address=a, change="seen_removed", reason=existing[a].reason)
        existing[a].delete()
    for a, e in remote.items():
        if a in existing and existing[a].reason != e.get("Reason", ""):
            SuppressionEntry.objects.filter(pk=existing[a].pk).update(reason=e.get("Reason", ""), last_update_time=e.get("LastUpdateTime"))
    return len(added), len(removed)


def mirror_removed(account_id, region, addresses, actor):
    """After a console-driven removal, update the mirror immediately and record who did it."""
    for a in addresses:
        row = SuppressionEntry.objects.filter(aws_account_id=account_id, region=region, address=a).first()
        SuppressionChange.objects.create(aws_account_id=account_id, region=region, address=a, change="removed",
                                         reason=row.reason if row else "", actor=actor)
        SuppressionEntry.objects.filter(aws_account_id=account_id, region=region, address=a).delete()
