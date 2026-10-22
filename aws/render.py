#!/usr/bin/env python3
"""Fill the placeholders in aws/policies/*.json and write files ready to hand to the AWS CLI.

    python3 aws/render.py --account-id 123456789012 --region ap-south-1 --email-domain example.com \
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
import sys

POLICY_DIR = pathlib.Path(__file__).resolve().parent / "policies"
PLACEHOLDER = re.compile(r"__[A-Z_]+__")

CHECKS = {
    "__ACCOUNT_ID__": (r"\d{12}", "a 12-digit AWS account id"),
    "__REGION__": (r"[a-z]{2}(-[a-z]+)+-\d", "a region such as ap-south-1"),
    "__EMAIL_DOMAIN__": (r"([a-z0-9-]+\.)+[a-z]{2,}", "your organisation's e-mail domain, such as example.com"),
    "__TOPIC_ARN__": (r"arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+", "an SNS topic ARN"),
    "__QUEUE_ARN__": (r"arn:aws:sqs:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+", "an SQS queue ARN"),
    "__SERVICE_PRINCIPAL__": (r"[a-z0-9-]+\.amazonaws\.com", "the AWS service that runs the console, such as ec2.amazonaws.com or ecs-tasks.amazonaws.com"),
}
APP_ROLE_NAME = "mail-console-app"


def build_values(args):
    values = {
        "__ACCOUNT_ID__": args.account_id, "__REGION__": args.region, "__EMAIL_DOMAIN__": args.email_domain.lower(),
        "__TOPIC_ARN__": args.topic_arn, "__QUEUE_ARN__": args.queue_arn, "__SERVICE_PRINCIPAL__": args.service_principal,
    }
    for token, (pattern, what) in CHECKS.items():
        if not re.fullmatch(pattern, values[token]):
            raise SystemExit(f"{token}: {values[token]!r} is not {what}")
    values["__APP_ROLE_ARN__"] = f"arn:aws:iam::{values['__ACCOUNT_ID__']}:role/{APP_ROLE_NAME}"
    return values


def render(values):
    """Return {filename: text} for every policy, plus the SQS attributes wrapper."""
    out = {}
    for path in sorted(POLICY_DIR.glob("*.json")):
        text = path.read_text()
        for token, value in values.items():
            text = text.replace(token, value)
        left = set(PLACEHOLDER.findall(text))
        if left:
            raise SystemExit(f"{path.name}: unfilled placeholders {sorted(left)}")
        json.loads(text)  # must still be valid JSON after substitution
        out[path.name] = text
    # `aws sqs set-queue-attributes` wants the policy as a JSON *string* inside an attributes map.
    out["sqs-queue-attributes.json"] = json.dumps({"Policy": json.dumps(json.loads(out["sqs-queue-policy.json"]))}, indent=2) + "\n"
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--account-id", required=True)
    ap.add_argument("--region", required=True)
    ap.add_argument("--email-domain", required=True, help="people who may use the write roles must have an address at this domain")
    ap.add_argument("--topic-arn", required=True)
    ap.add_argument("--queue-arn", required=True)
    ap.add_argument("--service-principal", required=True)
    ap.add_argument("--out", default="aws-rendered")
    args = ap.parse_args(argv)
    files = render(build_values(args))
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    print(f"wrote {len(files)} files to {out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
