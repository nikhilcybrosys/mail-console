#!/usr/bin/env python3
"""Fill the placeholders in aws/policies/*.json and write files ready to hand to the AWS CLI.

    python3 aws/render.py --account-id 123456789012 --region ap-south-1 --allowed-email you@example.com --allowed-email colleague@example.com \
        --topic-arn arn:aws:sns:ap-south-1:123456789012:mail-console-ses-events \
        --queue-arn arn:aws:sqs:ap-south-1:123456789012:mail-console-events \
        --service-principal ec2.amazonaws.com

Everything is validated before anything is written, and any placeholder left unfilled is an error, so you cannot apply a
half-rendered policy. The output directory (default ./aws-rendered) is git-ignored.
"""
import argparse
import json
import pathlib
import re
import secrets
import sys

POLICY_DIR = pathlib.Path(__file__).resolve().parent / "policies"
PLACEHOLDER = re.compile(r"__[A-Z_]+__")

CHECKS = {
    "__ACCOUNT_ID__": (r"\d{12}", "a 12-digit AWS account id"),
    "__REGION__": (r"[a-z]{2}(-[a-z]+)+-\d", "a region such as ap-south-1"),
    "__TOPIC_ARN__": (r"arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+", "an SNS topic ARN"),
    "__QUEUE_ARN__": (r"arn:aws:sqs:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+", "an SQS queue ARN"),
    "__EXTERNAL_ID__": (r"[A-Za-z0-9+=,.@:/_-]{24,256}", "a secret of 24 to 256 letters, digits or + = , . @ : / _ -"),
    "__SERVICE_PRINCIPAL__": (r"[a-z0-9-]+\.amazonaws\.com", "the AWS service that runs the console, such as ec2.amazonaws.com or ecs-tasks.amazonaws.com"),
}
ARCHIVE_CHECKS = {
    "__ARCHIVE_ARN__": (r"arn:aws:ses:[a-z0-9-]+:\d{12}:mailmanager-archive/a-\w{1,64}", "an SES Mail Manager archive ARN"),
    "__ARCHIVE_KMS_KEY_ARN__": (r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}", "the ARN of the KMS key that encrypts the archive"),
}
DMARC_CHECKS = {
    "__DMARC_QUEUE_ARN__": (r"arn:aws:sqs:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+", "an SQS queue ARN"),
    "__DMARC_TOPIC_ARN__": (r"arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+", "an SNS topic ARN"),
    "__DMARC_BUCKET__": (r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", "an S3 bucket name"),
    "__DMARC_PREFIX__": (r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/", "a folder-style prefix ending in /, such as dmarc/"),
    "__DMARC_RULE_SET__": (r"[A-Za-z0-9_-]{1,64}", "a receipt rule set name (letters, digits, _ and -)"),
    "__DMARC_RULE__": (r"[A-Za-z0-9_-]{1,64}", "a receipt rule name (letters, digits, _ and -)"),
}
APP_ROLE_NAME = "mail-console-app"
# Compose is opt-in: these four files are only produced when --send-email and --send-from are given.
SEND_FILES = {"send.json", "permissions-boundary-send.json", "trust-send-role.json", "app-assume-send.json"}
# DMARC collection by mail is opt-in too: these files are only produced when the --dmarc-* options are given.
DMARC_FILES = {"dmarc-inbound.json", "dmarc-queue-policy.json", "dmarc-topic-policy.json", "dmarc-bucket-policy.json"}
# Reading the sent-mail archive is opt-in too (--archive-arn and --archive-kms-key-arn).
ARCHIVE_FILES = {"archive-read.json"}
# Each opt-in feature may need one more narrow allowance in the console roles' permissions boundary (a boundary only caps what the
# roles can be granted). The statements live in fragments/ and are merged into ONE extended boundary, so any combination works.
FRAGMENTS = {"boundary-dmarc.json": "__DMARC_QUEUE_ARN__", "boundary-archive.json": "__ARCHIVE_ARN__"}
EXTENDED_BOUNDARY = "permissions-boundary-extended.json"
LIST_TOKENS = ("__ALLOWED_EMAILS__", "__SEND_EMAILS__", "__SEND_FROM__", "__SEND_RESOURCES__")
CONFIG_SET = re.compile(r"[A-Za-z0-9_-]{1,64}")
EMAIL = re.compile(r"[a-z0-9._%+-]{1,40}@([a-z0-9-]+\.)+[a-z]{2,}")  # exact, lowercase, no wildcards: SourceIdentity is matched exactly


def clean_emails(raw):
    emails = []
    for e in raw or []:
        e = e.strip().lower()
        if not EMAIL.fullmatch(e) or len(e) > 64:  # 64 is the SourceIdentity length limit
            raise SystemExit(f"--allowed-email {e!r} is not a plain e-mail address (no wildcards; at most 64 characters)")
        if e not in emails:
            emails.append(e)
    if not emails:
        raise SystemExit("give at least one --allowed-email: the people who may use the console's write roles")
    if len(emails) > 25:
        raise SystemExit("at most 25 allowed e-mail addresses")
    return emails


def clean_addresses(raw, flag, what, limit=25):
    out = []
    for e in raw or []:
        e = e.strip().lower()
        if not EMAIL.fullmatch(e) or len(e) > 64:
            raise SystemExit(f"{flag} {e!r} is not a plain e-mail address (no wildcards; at most 64 characters)")
        if e not in out:
            out.append(e)
    if len(out) > limit:
        raise SystemExit(f"at most {limit} {what}")
    return out


def build_values(args):
    values = {
        "__ACCOUNT_ID__": args.account_id, "__REGION__": args.region,
        "__TOPIC_ARN__": args.topic_arn, "__QUEUE_ARN__": args.queue_arn, "__SERVICE_PRINCIPAL__": args.service_principal,
        "__EXTERNAL_ID__": args.external_id or secrets.token_urlsafe(32),
    }
    for token, (pattern, what) in CHECKS.items():
        if not re.fullmatch(pattern, values[token]):
            raise SystemExit(f"{token}: {values[token]!r} is not {what}")
    values["__ALLOWED_EMAILS__"] = clean_emails(args.allowed_email)
    send_emails = clean_addresses(getattr(args, "send_email", None), "--send-email", "people allowed to send")
    send_from = clean_addresses(getattr(args, "send_from", None), "--send-from", "From addresses")
    if bool(send_emails) != bool(send_from):
        raise SystemExit("Compose needs both --send-email (who may send) and --send-from (which addresses they may send as), or neither")
    config_set = (getattr(args, "send_config_set", "") or "").strip()
    if send_emails and not CONFIG_SET.fullmatch(config_set):
        raise SystemExit("Compose needs --send-config-set: the one configuration set its mail goes through (letters, digits, _ and -)")
    if config_set and not send_emails:
        raise SystemExit("--send-config-set only makes sense together with --send-email and --send-from")
    if send_emails:
        values["__SEND_EMAILS__"], values["__SEND_FROM__"], values["__SEND_CONFIG_SET__"] = send_emails, send_from, config_set
        # Only the identities behind the allowed From addresses (each address, and its domain) and the one configuration set.
        # IAM cannot require that a set is named; SES applies the identity's default set when none is, and naming any other
        # set is outside this resource list, so it is denied.
        names = []
        for a in send_from:
            for n in (a, a.split("@")[1]):
                if n not in names:
                    names.append(n)
        values["__SEND_RESOURCES__"] = [f"arn:aws:ses:{args.region}:{args.account_id}:identity/{n}" for n in names] + \
            [f"arn:aws:ses:{args.region}:{args.account_id}:configuration-set/{config_set}"]
    dmarc = {"__DMARC_QUEUE_ARN__": getattr(args, "dmarc_queue_arn", ""), "__DMARC_TOPIC_ARN__": getattr(args, "dmarc_topic_arn", ""),
             "__DMARC_BUCKET__": getattr(args, "dmarc_bucket", "")}
    if any(dmarc.values()) and not all(dmarc.values()):
        raise SystemExit("DMARC collection needs --dmarc-queue-arn, --dmarc-topic-arn and --dmarc-bucket together, or none of them")
    if all(dmarc.values()):
        dmarc.update({"__DMARC_PREFIX__": getattr(args, "dmarc_prefix", "") or "dmarc/", "__DMARC_RULE_SET__": getattr(args, "dmarc_rule_set", "") or "mail-console-dmarc",
                      "__DMARC_RULE__": getattr(args, "dmarc_rule", "") or "dmarc-reports"})
        for token, value in dmarc.items():
            if not re.fullmatch(DMARC_CHECKS[token][0], value):
                raise SystemExit(f"{token}: {value!r} is not {DMARC_CHECKS[token][1]}")
        if ".." in dmarc["__DMARC_PREFIX__"]:
            raise SystemExit("--dmarc-prefix must not contain ..")
        values.update(dmarc)
    archive = {"__ARCHIVE_ARN__": getattr(args, "archive_arn", ""), "__ARCHIVE_KMS_KEY_ARN__": getattr(args, "archive_kms_key_arn", "")}
    if any(archive.values()) and not all(archive.values()):
        raise SystemExit("The mail archive needs --archive-arn and --archive-kms-key-arn together, or neither")
    if all(archive.values()):
        for token, value in archive.items():
            if not re.fullmatch(ARCHIVE_CHECKS[token][0], value):
                raise SystemExit(f"{token}: {value!r} is not {ARCHIVE_CHECKS[token][1]}")
        if archive["__ARCHIVE_ARN__"].split(":")[3] != args.region or archive["__ARCHIVE_KMS_KEY_ARN__"].split(":")[3] != args.region:
            raise SystemExit("The archive and its key must be in the same region as --region")
        values.update(archive)
    values["__APP_ROLE_ARN__"] = f"arn:aws:iam::{values['__ACCOUNT_ID__']}:role/{APP_ROLE_NAME}"
    return values


def render(values):
    """Return {filename: text} for every policy, plus the SQS attributes wrapper."""
    out = {}
    for path in sorted(POLICY_DIR.glob("*.json")):
        if path.name in SEND_FILES and "__SEND_FROM__" not in values:
            continue  # Compose not requested: nothing about sending is rendered
        if path.name in DMARC_FILES and "__DMARC_QUEUE_ARN__" not in values:
            continue  # DMARC collection not requested: nothing about it is rendered
        if path.name in ARCHIVE_FILES and "__ARCHIVE_ARN__" not in values:
            continue  # the mail archive is not requested: nothing about it is rendered
        text = path.read_text()
        for token, value in values.items():
            if token in LIST_TOKENS:  # a JSON array, substituted for the whole quoted token
                text = text.replace(f'"{token}"', json.dumps(value))
            else:
                text = text.replace(token, value)
        left = set(PLACEHOLDER.findall(text))
        if left:
            raise SystemExit(f"{path.name}: unfilled placeholders {sorted(left)}")
        json.loads(text)  # must still be valid JSON after substitution
        out[path.name] = text
    # `aws sqs set-queue-attributes` wants the policy as a JSON *string* inside an attributes map.
    out["sqs-queue-attributes.json"] = json.dumps({"Policy": json.dumps(json.loads(out["sqs-queue-policy.json"]))}, indent=2) + "\n"
    extra = []
    for name, token in FRAGMENTS.items():
        if token in values:
            frag = (POLICY_DIR / "fragments" / name).read_text()
            for t, v in values.items():
                if t not in LIST_TOKENS:
                    frag = frag.replace(t, v)
            left = set(PLACEHOLDER.findall(frag))
            if left:
                raise SystemExit(f"fragments/{name}: unfilled placeholders {sorted(left)}")
            extra += json.loads(frag)
    if extra:
        boundary = json.loads(out["permissions-boundary.json"])
        boundary["Statement"][1:1] = extra          # after the ceiling, before the denies: order has no effect, readability only
        out[EXTENDED_BOUNDARY] = json.dumps(boundary, indent=2) + "\n"
    if "dmarc-queue-policy.json" in out:
        out["dmarc-queue-attributes.json"] = json.dumps({"Policy": json.dumps(json.loads(out["dmarc-queue-policy.json"]))}, indent=2) + "\n"
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--account-id", required=True)
    ap.add_argument("--region", required=True)
    ap.add_argument("--allowed-email", action="append", default=[], help="an e-mail address allowed to act through the write roles (repeat for several)")
    ap.add_argument("--send-email", action="append", default=[], help="Compose (optional): an e-mail address allowed to send mail through the console (repeat)")
    ap.add_argument("--send-from", action="append", default=[], help="Compose (optional): an address the console may send as, exactly (repeat)")
    ap.add_argument("--send-config-set", default="", help="Compose (optional): the single configuration set its mail goes through")
    ap.add_argument("--dmarc-queue-arn", default="", help="DMARC by mail (optional): the queue that receives the report notifications")
    ap.add_argument("--dmarc-topic-arn", default="", help="DMARC by mail (optional): the SNS topic the SES receipt rule publishes to")
    ap.add_argument("--dmarc-bucket", default="", help="DMARC by mail (optional): the S3 bucket SES stores the raw report mail in")
    ap.add_argument("--dmarc-prefix", default="", help="folder inside that bucket (default dmarc/)")
    ap.add_argument("--dmarc-rule-set", default="", help="SES receipt rule set name (default mail-console-dmarc)")
    ap.add_argument("--dmarc-rule", default="", help="SES receipt rule name (default dmarc-reports)")
    ap.add_argument("--archive-arn", default="", help="Mail archive (optional): the SES Mail Manager archive that holds copies of sent mail")
    ap.add_argument("--archive-kms-key-arn", default="", help="Mail archive (optional): the KMS key that encrypts that archive")
    ap.add_argument("--topic-arn", required=True)
    ap.add_argument("--queue-arn", required=True)
    ap.add_argument("--service-principal", required=True)
    ap.add_argument("--external-id", default="", help="shared secret the write roles require; generated if omitted (it is printed once)")
    ap.add_argument("--out", default="aws-rendered")
    args = ap.parse_args(argv)
    values = build_values(args)
    files = render(values)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    print(f"wrote {len(files)} files to {out}/")
    print(f"\nMC_AWS_WRITE_ROLE_EXTERNAL_ID={values['__EXTERNAL_ID__']}\n(set this in the console's environment; it is also inside {out}/trust-write-roles.json. Treat it as a secret.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
