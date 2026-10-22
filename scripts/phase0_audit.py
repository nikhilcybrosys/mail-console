#!/usr/bin/env python3
"""Phase 0: READ-ONLY audit of the real SES state. Run by a human with their own AWS profile.

    AWS_PROFILE=<profile> python scripts/phase0_audit.py --regions ap-south-1 us-east-1

The report contains account details and IAM key suffixes, so it is written OUTSIDE the repository (default:
~/ses-audit-report.json) and the script refuses to write inside it. Never commit or share it.

Safety: every boto3 client is wrapped so ONLY get_/list_/describe_ calls can execute; any other
method raises before reaching AWS. It never prints credentials and never reads SMTP passwords.
It answers: is production really on SES? which regions/identities/config sets? sandbox? suppression size?
which IAM users can send via SES (the stray N. Virginia ses-smtp-user)?
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import sys

import boto3

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def resolve_out(path):
    """Where to write the report. Refuses any location inside this repository (it is public)."""
    out = pathlib.Path(path).expanduser().resolve()
    if out == REPO_ROOT or REPO_ROOT in out.parents:
        raise SystemExit(f"refusing to write the report inside the repository ({out}): it contains account details. Choose a path outside it.")
    return out


ALLOWED_PREFIXES = ("get_", "list_", "describe_", "batch_get_", "can_paginate", "get_paginator", "meta", "exceptions")


class ReadOnly:
    def __init__(self, client):
        self._c = client

    def __getattr__(self, name):
        if not name.startswith(ALLOWED_PREFIXES) and name not in ("exceptions", "meta"):
            raise PermissionError(f"phase0_audit is read-only: refusing {name}()")
        return getattr(self._c, name)


def client(service, region=None):
    return ReadOnly(boto3.client(service, region_name=region))


def safe(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Exception as exc:  # report, never crash the whole audit
        return {"_error": f"{type(exc).__name__}: {str(exc)[:200]}"}


def audit_region(region, ses=None, cw=None):
    ses = ses or client("sesv2", region)
    out = {"region": region}
    acct = safe(ses.get_account)
    out["account"] = acct if "_error" in acct else {
        "production_access": acct.get("ProductionAccessEnabled"), "sending_enabled": acct.get("SendingEnabled"),
        "enforcement": acct.get("EnforcementStatus"), "quota": acct.get("SendQuota"),
        "suppression_reasons": acct.get("SuppressionAttributes", {}).get("SuppressedReasons"),
        "vdm": acct.get("VdmAttributes", {}).get("VdmEnabled"), "details_status": acct.get("Details", {}).get("ReviewDetails", {}).get("Status")}
    ids = safe(ses.list_email_identities, PageSize=100)
    out["identities"] = []
    for i in ([] if "_error" in ids else ids.get("EmailIdentities", [])):
        d = safe(ses.get_email_identity, EmailIdentity=i["IdentityName"])
        out["identities"].append({"name": i["IdentityName"], "type": i.get("IdentityType"), "verified": d.get("VerifiedForSendingStatus") if "_error" not in d else None,
                                  "dkim": d.get("DkimAttributes", {}).get("Status") if "_error" not in d else d,
                                  "dkim_origin": d.get("DkimAttributes", {}).get("SigningAttributesOrigin") if "_error" not in d else None,
                                  "mail_from": d.get("MailFromAttributes", {}).get("MailFromDomain") if "_error" not in d else None,
                                  "default_config_set": d.get("ConfigurationSetName") if "_error" not in d else None})
    cs = safe(ses.list_configuration_sets, PageSize=100)
    out["config_sets"] = []
    for n in ([] if "_error" in cs else cs.get("ConfigurationSets", [])):
        dests = safe(ses.get_configuration_set_event_destinations, ConfigurationSetName=n)
        out["config_sets"].append({"name": n, "destinations": [{"name": x.get("Name"), "enabled": x.get("Enabled"), "events": x.get("MatchingEventTypes"),
                                                                 "kind": [k for k in ("SnsDestination", "KinesisFirehoseDestination", "CloudWatchDestination", "EventBridgeDestination") if k in x]}
                                                                for x in dests.get("EventDestinations", [])] if "_error" not in dests else dests})
    count, token = 0, None
    for _ in range(200):  # cap at 200k addresses
        r = safe(ses.list_suppressed_destinations, PageSize=1000, **({"NextToken": token} if token else {}))
        if "_error" in r:
            out["suppression_count"] = r
            break
        count += len(r.get("SuppressedDestinationSummaries", []))
        token = r.get("NextToken")
        if not token:
            out["suppression_count"] = count
            break
    cw = cw or client("cloudwatch", region)
    end = dt.datetime.now(dt.timezone.utc)
    m = safe(cw.get_metric_data, MetricDataQueries=[{"Id": "s", "MetricStat": {"Metric": {"Namespace": "AWS/SES", "MetricName": "Send"}, "Period": 86400, "Stat": "Sum"}}],
             StartTime=end - dt.timedelta(days=14), EndTime=end)
    out["sends_last_14d_daily"] = m if "_error" in m else [round(v) for v in m["MetricDataResults"][0].get("Values", [])]
    return out


SES_NAME = re.compile(r"(^|[^a-z])(ses|smtp)([^a-z]|$)|amazonses|email-smtp", re.I)  # "ses" as a word, not inside "James"


def _all_users(iam):
    users, marker = [], None
    while True:
        r = safe(iam.list_users, **({"Marker": marker} if marker else {}))
        if "_error" in r:
            return r
        users += r.get("Users", [])
        if not r.get("IsTruncated"):
            return users
        marker = r.get("Marker")


def _mentions_ses(doc):
    text = json.dumps(doc, default=str).lower()
    return "ses:" in text or "amazonses" in text


def _key_info(iam, key):
    last = safe(iam.get_access_key_last_used, AccessKeyId=key["AccessKeyId"])
    info = {"id_suffix": key["AccessKeyId"][-4:], "status": key["Status"], "created": str(key["CreateDate"])[:10]}  # never the full id
    if "_error" in last:
        return {**info, "last_used": last}
    u = last.get("AccessKeyLastUsed", {})
    when = u.get("LastUsedDate")
    return {**info, "last_used": str(when)[:10] if when else None, "last_used_service": u.get("ServiceName") if when else None,
            "last_used_region": u.get("Region") if when else None}


def _group_reasons(iam, user):
    """Why this user may be able to use SES through the groups it belongs to."""
    groups = safe(iam.list_groups_for_user, UserName=user)
    reasons = []
    for g in ([] if "_error" in groups else groups.get("Groups", [])):
        gname = g["GroupName"]
        attached = safe(iam.list_attached_group_policies, GroupName=gname)
        if any(re.search(r"ses|email", x["PolicyName"], re.I) for x in ([] if "_error" in attached else attached.get("AttachedPolicies", []))):
            reasons.append(f"member of group {gname!r}, which has an SES-related attached policy")
        inline = safe(iam.list_group_policies, GroupName=gname)
        for pn in ([] if "_error" in inline else inline.get("PolicyNames", [])):
            doc = safe(iam.get_group_policy, GroupName=gname, PolicyName=pn)
            if "_error" not in doc and _mentions_ses(doc.get("PolicyDocument", {})):
                reasons.append(f"member of group {gname!r}, whose inline policy {pn!r} mentions SES permissions")
    return reasons


def audit_iam(iam=None):
    """Users that look SES-related, with the reason and when each access key was last used (None = never)."""
    iam = iam or client("iam")
    users = _all_users(iam)
    if isinstance(users, dict):
        return [users]
    res = []
    for u in users:
        n = u["UserName"]
        pol = safe(iam.list_attached_user_policies, UserName=n)
        inline = safe(iam.list_user_policies, UserName=n)
        names = [] if "_error" in pol else [p["PolicyName"] for p in pol.get("AttachedPolicies", [])]
        inl = [] if "_error" in inline else inline.get("PolicyNames", [])
        reasons = []
        if SES_NAME.search(n):
            reasons.append("name looks SES/SMTP-related")
        reasons += _group_reasons(iam, n)  # permissions inherited through groups are easy to miss
        if any(re.search(r"ses|email", x, re.I) for x in names):
            reasons.append("an attached policy looks SES-related")
        for pn in inl:
            doc = safe(iam.get_user_policy, UserName=n, PolicyName=pn)
            if "_error" not in doc and _mentions_ses(doc.get("PolicyDocument", {})):
                reasons.append(f"inline policy {pn!r} mentions SES permissions")
        if reasons:
            keys = safe(iam.list_access_keys, UserName=n)
            res.append({"user": n, "why": reasons, "attached": names, "inline": inl, "created": str(u.get("CreateDate"))[:10],
                        "keys": [] if "_error" in keys else [_key_info(iam, k) for k in keys.get("AccessKeyMetadata", [])]})
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regions", nargs="+", default=["ap-south-1"])
    ap.add_argument("--out", default="~/ses-audit-report.json", help="must be outside the repository")
    a = ap.parse_args()
    out_path = resolve_out(a.out)  # fail before touching AWS
    who = safe(client("sts").get_caller_identity)
    report = {"generated": dt.datetime.now(dt.timezone.utc).isoformat(), "caller": {k: who.get(k) for k in ("Account", "Arn")} if "_error" not in who else who,
              "regions": [audit_region(r) for r in a.regions], "iam_ses_related_users": audit_iam()}
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    out_path.chmod(0o600)  # owner-only
    print(f"wrote {out_path} (private: contains account details, do not commit or share)")
    for r in report["regions"]:
        acc = r["account"]
        print(f"[{r['region']}] production={acc.get('production_access') if isinstance(acc, dict) else '?'} identities={len(r['identities'])} "
              f"config_sets={len(r['config_sets'])} suppressed={r.get('suppression_count')} sends14d={r.get('sends_last_14d_daily')}")
    for u in report["iam_ses_related_users"]:
        if "user" not in u:
            print(f"[iam] could not list users: {u.get('_error')}")
            continue
        keys = ", ".join(f"...{k['id_suffix']} {k['status']} last used {k['last_used'] or 'NEVER'}" for k in u["keys"]) or "no keys"
        print(f"[iam] {u['user']}: {'; '.join(u['why'])}; {keys}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
