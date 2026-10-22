#!/usr/bin/env python3
"""Phase 0: READ-ONLY audit of the real SES state. Run by a human with their own AWS profile.

    AWS_PROFILE=<profile> python scripts/phase0_audit.py --regions ap-south-1 us-east-1 --out phase0-report.md

Safety: every boto3 client is wrapped so ONLY get_/list_/describe_ calls can execute; any other
method raises before reaching AWS. It never prints credentials and never reads SMTP passwords.
It answers: is production really on SES? which regions/identities/config sets? sandbox? suppression size?
which IAM users can send via SES (the stray N. Virginia ses-smtp-user)?
"""
import argparse
import datetime as dt
import json
import sys

import boto3

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


def audit_region(region):
    ses = client("sesv2", region)
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
        out["identities"].append({"name": i["IdentityName"], "type": i.get("IdentityType"), "verified": i.get("VerifiedForSendingStatus"),
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
    cw = client("cloudwatch", region)
    end = dt.datetime.now(dt.timezone.utc)
    m = safe(cw.get_metric_data, MetricDataQueries=[{"Id": "s", "MetricStat": {"Metric": {"Namespace": "AWS/SES", "MetricName": "Send"}, "Period": 86400, "Stat": "Sum"}}],
             StartTime=end - dt.timedelta(days=14), EndTime=end)
    out["sends_last_14d_daily"] = m if "_error" in m else [round(v) for v in m["MetricDataResults"][0].get("Values", [])]
    return out


def audit_iam():
    iam = client("iam")
    users = safe(iam.list_users)
    res = []
    for u in ([] if "_error" in users else users.get("Users", [])):
        n = u["UserName"]
        pol = safe(iam.list_attached_user_policies, UserName=n)
        inline = safe(iam.list_user_policies, UserName=n)
        keys = safe(iam.list_access_keys, UserName=n)
        names = [] if "_error" in pol else [p["PolicyName"] for p in pol.get("AttachedPolicies", [])]
        inl = [] if "_error" in inline else inline.get("PolicyNames", [])
        if any("ses" in x.lower() or "email" in x.lower() for x in names + inl) or "smtp" in n.lower() or "ses" in n.lower():
            res.append({"user": n, "attached": names, "inline": inl, "created": str(u.get("CreateDate")),
                        "keys": [] if "_error" in keys else [{"id_suffix": k["AccessKeyId"][-4:], "status": k["Status"], "created": str(k["CreateDate"])} for k in keys.get("AccessKeyMetadata", [])]})
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regions", nargs="+", default=["ap-south-1"])
    ap.add_argument("--out", default="phase0-report.json")
    a = ap.parse_args()
    who = safe(client("sts").get_caller_identity)
    report = {"generated": dt.datetime.now(dt.timezone.utc).isoformat(), "caller": {k: who.get(k) for k in ("Account", "Arn")} if "_error" not in who else who,
              "regions": [audit_region(r) for r in a.regions], "iam_ses_related_users": audit_iam()}
    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"wrote {a.out}")
    for r in report["regions"]:
        acc = r["account"]
        print(f"[{r['region']}] production={acc.get('production_access') if isinstance(acc, dict) else '?'} identities={len(r['identities'])} "
              f"config_sets={len(r['config_sets'])} suppressed={r.get('suppression_count')} sends14d={r.get('sends_last_14d_daily')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
