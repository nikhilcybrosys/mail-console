# Connecting Mail Console to your AWS account

This is everything Mail Console needs from AWS, as a handful of AWS CLI commands and IAM policy files. There is no
infrastructure-as-code to apply and no hosting stack: run the console wherever you like (one small server is plenty).

```
SES  ->  configuration set  ->  SNS topic  ->  SQS queue (+ dead-letter queue)  ->  console worker  ->  database
```

and three IAM roles, all capped by a permissions boundary, **none of which can send mail**:

| Role | What it can do |
|---|---|
| `mail-console-app` | Read SES state, read reputation metrics, consume the event queue, and *request* the two write roles (only as a named, allow-listed person). |
| `mail-console-write-ops` | Add or remove suppression-list entries. Assumed per approved action. |
| `mail-console-write-security` | Delete identities, change DKIM and MAIL FROM, change event destinations and account sending settings. Assumed per approved action. |

> **Status: not yet run against a real AWS account.** The policy files are verified by automated tests
> (`tests/test_aws_policies.py`: no console role can send mail, write access needs a named person, and the policies match
> exactly what the code calls), but AWS itself has not evaluated them. Try this in a non-production account first, and
> check the result with the policy simulator (step 7).

## Where to run it: its own small server
Give the console its own small instance (or container host) that runs nothing else, about $10 to 15 a month. This matters more
than it looks:

- An instance role applies to **every process on the machine**: anything that can reach the instance metadata service can use
  the app role, including asking for the two write roles. The write roles only require that the caller names a person
  (`sts:SourceIdentity`); the **approval step is enforced by the console application, not by IAM**. So if any other program on a
  shared host is compromised, an attacker can change SES settings (delete an identity, pause sending, edit the suppression list,
  remove the event destination) without an approval. They still cannot send mail, but they can stop yours.
- The console also shows recipient addresses and subjects, and renders untrusted email. Keep it away from servers that hold
  billing, customer or production data, and away from public demo machines.
- The write roles also require a **shared secret** (`MC_AWS_WRITE_ROLE_EXTERNAL_ID`) that only the console knows, which blocks the
  easiest abuse on a shared server. Keep the secret in a file readable only by the console's own user, and run the console as its
  own unprivileged user. It is not a substitute for a dedicated host: anything running as root, or able to read the console's
  environment, still wins.
- An EC2 instance can have only **one** instance profile, so putting the console on an existing server would mean merging its
  permissions into that server's role.

Require IMDSv2 on the instance (`aws ec2 modify-instance-metadata-options --instance-id i-... --http-tokens required`). If you
run the console in Docker with default networking, also set `--http-put-response-hop-limit 2`, otherwise the container cannot
reach the metadata service. Allow inbound traffic on port 443 only, and restrict it to your office or VPN addresses if you can.

## What you need
- AWS CLI v2 signed in with rights to create IAM roles and policies, SNS topics, SQS queues, and to edit SES configuration sets.
- Python 3 (only to fill in the policy placeholders) and a checkout of this repository.
- An SES **configuration set** that your identities use by default. Most accounts already have one (the console creates
  `my-first-configuration-set`). Check in step 4.

## 1. Queues and topic

```bash
export AWS_REGION=ap-south-1 AWS_DEFAULT_REGION=ap-south-1
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ALLOWED_EMAILS="you@example.com colleague@example.com"   # exactly who may act through the write roles (lowercase)

# Dead-letter queue first, then the main queue that points at it.
DLQ_URL=$(aws sqs create-queue --queue-name mail-console-events-dlq \
  --attributes MessageRetentionPeriod=1209600,SqsManagedSseEnabled=true --query QueueUrl --output text)
DLQ_ARN=$(aws sqs get-queue-attributes --queue-url "$DLQ_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)

cat > /tmp/mc-queue-attrs.json <<JSON
{"SqsManagedSseEnabled": "true", "VisibilityTimeout": "120", "MessageRetentionPeriod": "1209600",
 "RedrivePolicy": "{\"deadLetterTargetArn\":\"$DLQ_ARN\",\"maxReceiveCount\":\"5\"}"}
JSON
QUEUE_URL=$(aws sqs create-queue --queue-name mail-console-events --attributes file:///tmp/mc-queue-attrs.json --query QueueUrl --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)

TOPIC_ARN=$(aws sns create-topic --name mail-console-ses-events --query TopicArn --output text)
```

The topic is left unencrypted on purpose: SES cannot publish to a topic encrypted with the AWS-managed SNS key. Events
carry recipient addresses, subjects and delivery details but never message bodies. If you need encryption, use a
customer-managed KMS key whose policy lets `ses.amazonaws.com` use it (see the AWS documentation for event publishing).

## 2. Fill in the policies

```bash
python3 aws/render.py --account-id "$ACCOUNT_ID" --region "$AWS_REGION" $(for e in $ALLOWED_EMAILS; do printf -- "--allowed-email %s " "$e"; done) \
  --topic-arn "$TOPIC_ARN" --queue-arn "$QUEUE_ARN" --service-principal ec2.amazonaws.com
```

It also **prints a secret** (`MC_AWS_WRITE_ROLE_EXTERNAL_ID`): the write roles only accept a caller that presents it, so other programs that share the
server cannot use the instance credentials to change SES settings. Put it in the console's environment file and nowhere else. This writes ready-to-use files to `./aws-rendered/` (git-ignored; they contain your account id) and refuses to continue if
anything is invalid or left unfilled. Use `--service-principal ecs-tasks.amazonaws.com` if the console runs on ECS.
The write roles accept only the exact addresses you list (AWS's policy checker rejects a domain-wide wildcard as too permissive). Edit `aws/policies/*.json` first if you need a second region: the region condition is a single value.

## 3. Wire the queue and topic together

```bash
aws sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes file://aws-rendered/sqs-queue-attributes.json
aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy --attribute-value file://aws-rendered/sns-topic-policy.json
aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol sqs --notification-endpoint "$QUEUE_ARN"
```

The queue accepts messages only from this topic, and the topic accepts publishes only from SES in your account.

## 4. IAM roles

```bash
BOUNDARY_ARN=$(aws iam create-policy --policy-name mail-console-boundary \
  --policy-document file://aws-rendered/permissions-boundary.json --query Policy.Arn --output text)

# The app role comes first: the write roles trust it.
aws iam create-role --role-name mail-console-app --permissions-boundary "$BOUNDARY_ARN" \
  --assume-role-policy-document file://aws-rendered/trust-app-role.json
aws iam put-role-policy --role-name mail-console-app --policy-name console-read \
  --policy-document file://aws-rendered/console-read.json

for tier in ops security; do
  aws iam create-role --role-name "mail-console-write-$tier" --permissions-boundary "$BOUNDARY_ARN" \
    --assume-role-policy-document file://aws-rendered/trust-write-roles.json
  aws iam put-role-policy --role-name "mail-console-write-$tier" --policy-name "write-$tier" \
    --policy-document "file://aws-rendered/write-$tier.json"
done
```

If the console runs on a single EC2 instance, give it the app role (no access keys anywhere):

```bash
aws iam create-instance-profile --instance-profile-name mail-console-app
aws iam add-role-to-instance-profile --instance-profile-name mail-console-app --role-name mail-console-app
aws ec2 associate-iam-instance-profile --instance-id i-0123456789abcdef0 --iam-instance-profile Name=mail-console-app
```

## 5. Point SES at the topic

First see which configuration set your identities send through. This is the whole reason you could not see anything before:
a set with no event destination publishes nothing.

```bash
aws sesv2 list-configuration-sets
aws sesv2 get-email-identity --email-identity "$EMAIL_DOMAIN" --query ConfigurationSetName --output text
aws sesv2 get-configuration-set-event-destinations --configuration-set-name my-first-configuration-set
```

Then add an event destination to that **existing** set. Senders need no change:

```bash
cat > /tmp/mc-destination.json <<JSON
{"Enabled": true,
 "MatchingEventTypes": ["SEND", "REJECT", "BOUNCE", "COMPLAINT", "DELIVERY", "DELIVERY_DELAY", "RENDERING_FAILURE", "SUBSCRIPTION"],
 "SnsDestination": {"TopicArn": "$TOPIC_ARN"}}
JSON
aws sesv2 create-configuration-set-event-destination --configuration-set-name my-first-configuration-set \
  --event-destination-name mail-console --event-destination file:///tmp/mc-destination.json
```

If an identity has no default configuration set, give it one (mail from that identity is then covered automatically):

```bash
aws sesv2 put-email-identity-configuration-set-attributes --email-identity "$EMAIL_DOMAIN" --configuration-set-name my-first-configuration-set
```

**Never delete or replace a configuration set that is some identity's default**: every send from that identity then fails.
Add or remove *destinations* instead. Opens and clicks are not enabled above because they need tracking links.

Check that events arrive after the next email is sent:

```bash
aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names ApproximateNumberOfMessages
```

## 6. Run the console

Run the container image (see the root `Dockerfile`) or the Django app on any host that has the app role. Configuration is
environment variables:

| Variable | Value |
|---|---|
| `MC_SECRET_KEY` | a long random string (required) |
| `MC_DB_HOST`, `MC_DB_PORT`, `MC_DB_NAME`, `MC_DB_USER`, `MC_DB_PASSWORD` | your PostgreSQL 16 (set `MC_DB_SSLMODE=require` when it is remote) |
| `MC_CONSOLE_HOST` / `MC_MAILVIEW_HOST` | the console's host name, and a **separate registrable domain** for the sandboxed mail viewer, both pointing at the app behind TLS |
| `MC_WEBAUTHN_RP_ID`, `MC_WEBAUTHN_ORIGIN` | your console host name and `https://` origin (passkeys) |
| `MC_OIDC_DISCOVERY_URL`, `MC_OIDC_CLIENT_ID`, `MC_OIDC_CLIENT_SECRET`, `MC_OIDC_ALLOWED_DOMAIN` | your identity provider (see the root README, "Sign-in") |
| `AWS_DEFAULT_REGION`, `MC_AWS_REGIONS` | your SES region |
| `MC_SQS_EVENTS_QUEUE_URL` | `$QUEUE_URL` |
| `MC_EXPECTED_SNS_TOPIC_ARNS` | `$TOPIC_ARN` (the worker rejects messages from any other topic) |
| `MC_AWS_WRITE_ROLE_EXTERNAL_ID` | the secret printed by `aws/render.py` in step 2 (required: the write roles refuse a caller that does not present it) |
| `MC_AWS_WRITE_ROLE_OPS_ARN`, `MC_AWS_WRITE_ROLE_SECURITY_ARN` | `arn:aws:iam::<account>:role/mail-console-write-ops` and `...-security` |
| `MC_ALERT_SLACK_WEBHOOK_URL` | optional |

Run these processes (all use the same image or code):

| Process | Command | When |
|---|---|---|
| Web | the image default (`gunicorn config.wsgi:application`) | always |
| Event worker | `python manage.py ingest_ses_events` | always, restart on exit |
| State sync | `python manage.py sync_ses_state` | every 5 minutes (cron, a systemd timer, or a scheduled task) |
| One-time | `python manage.py migrate`, then `python manage.py register_aws_account main <account-id>`, then `python manage.py create_console_user you@example.com --role security_admin` | once |

Run the web process only behind a proxy that terminates TLS and sets `X-Forwarded-Proto` (the app trusts that header).

## 7. Prove the roles cannot send mail

```bash
APP_ROLE_ARN=arn:aws:iam::$ACCOUNT_ID:role/mail-console-app
aws iam simulate-principal-policy --policy-source-arn "$APP_ROLE_ARN" \
  --action-names ses:SendEmail ses:SendRawEmail ses:SendBulkEmail ses:GetAccount ses:DeleteSuppressedDestination \
  --resource-arns '*' --context-entries ContextKeyName=aws:RequestedRegion,ContextKeyValues="$AWS_REGION",ContextKeyType=string \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
```

Expected: the three `Send` actions are `explicitDeny`, `ses:GetAccount` is `allowed`, and `ses:DeleteSuppressedDestination`
is `implicitDeny` (the app role is read-only; only the write role, reached through an approval, can do that). Repeat with
`mail-console-write-ops` and `mail-console-write-security` as the source.

## Changing or removing things
Remove the SES event destination before deleting the topic, and delete the subscription before the queue. Delete the
roles in the reverse order of creation (write roles, then the app role, then the boundary policy). Do not delete the
configuration set. Because these steps are destructive, they are described here rather than given as a block to paste.
