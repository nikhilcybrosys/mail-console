# Connecting Mail Console to your AWS account

This is everything Mail Console needs from AWS, as a handful of AWS CLI commands and IAM policy files. There is no
infrastructure-as-code to apply and no hosting stack: run the console wherever you like (one small server is plenty).

```
SES  ->  configuration set  ->  SNS topic  ->  SQS queue (+ dead-letter queue)  ->  console worker  ->  database
```

and three IAM roles, all capped by a permissions boundary, **none of which can send mail** (an optional fourth role for hand-written mail, section 8, is the only exception and is off unless you create it):

| Role | What it can do |
|---|---|
| `mail-console-app` | Read SES state, read reputation metrics, consume the event queue, and *request* the two write roles (only as a named, allow-listed person). |
| `mail-console-write-ops` | Add or remove suppression-list entries. Assumed per approved action. |
| `mail-console-write-security` | Delete identities, change DKIM and MAIL FROM, change event destinations and account sending settings. Assumed per approved action. |

> **Status:** steps 1 to 5 have been applied to one real production account (Mumbai, ap-south-1) and checked there:
> the policies pass IAM Access Analyzer with no findings, a test event published to the topic arrived in the queue and
> was parsed by the app, and the policy simulator gave the results listed in step 7. The console process itself has not
> yet run against live events. Try this in a non-production account first if you can, and check the result with the policy
> simulator (step 7).

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

**Why the trust policies have three statements.** AWS does not supply `sts:ExternalId` when it checks `sts:SetSourceIdentity`, so
one statement that grants both and requires the secret denies every assumption (found by trying it for real: the policy
simulator said it was fine). The trust policies therefore *allow* AssumeRole with the secret, *allow* SetSourceIdentity for the named
people, and *deny* both actions for any other SourceIdentity. The deny is what makes a named person mandatory: Allows are ORed,
and a request with no SourceIdentity at all counts as "not in the list". Do not put an `sts:SourceIdentity` condition on the app
role's own assume statements either: AWS does not evaluate it there for SetSourceIdentity.

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
`mail-console-write-ops` and `mail-console-write-security` as the source. Their permissions apply only to a named
person, so add a second context entry such as `ContextKeyName=aws:SourceIdentity,ContextKeyValues=you@example.com,ContextKeyType=string`
(with your allowed address, then with a different one, which must stay `implicitDeny`).

The simulator does not set `aws:RequestedRegion` or `aws:SourceIdentity` for you. Without them it reports the region
guard as `explicitDeny` even for allowed read calls, which looks like a bug but is the simulator missing context.

## 8. Compose (optional): send one-off mail from the console
Off by default. Nothing below exists in AWS unless you do it, and the three roles above are unchanged and still cannot send.

Compose adds one more role, `mail-console-send`. IAM enforces **who** (only the people you list, through the app role and the
shared secret), **as which address** (`ses:FromAddress`, exact addresses), **on which identities and configuration set**, and
**in one region**. All other send actions are explicitly denied. What IAM cannot do: under SESv2, raw and templated content
travel through the same `ses:SendEmail` permission, so IAM cannot allow "simple" and forbid "raw". The console only ever builds
simple content (its sender object has no other method, and a test pins that). A configuration set cannot be *required* by IAM
either; the role may use only the one you name, and SES applies the identity's default set when none is named, so give your
identities that set as their default (step 5).

Render with three more options, then create the role:

```bash
python3 aws/render.py ... --send-email you@example.com --send-from notifications@example.com --send-from support@example.com \
  --send-config-set my-first-configuration-set

SEND_BOUNDARY_ARN=$(aws iam create-policy --policy-name mail-console-send-boundary \
  --policy-document file://aws-rendered/permissions-boundary-send.json --query Policy.Arn --output text)
aws iam create-role --role-name mail-console-send --permissions-boundary "$SEND_BOUNDARY_ARN" \
  --assume-role-policy-document file://aws-rendered/trust-send-role.json
aws iam put-role-policy --role-name mail-console-send --policy-name send --policy-document file://aws-rendered/send.json
aws iam put-role-policy --role-name mail-console-app --policy-name assume-send --policy-document file://aws-rendered/app-assume-send.json
```

Then set, in the console's environment:

| Variable | Value |
|---|---|
| `MC_SEND_ENABLED` | `1` |
| `MC_SEND_FROM_ADDRESSES` | the same addresses you gave `--send-from`, comma separated (the most the console will ever offer) |
| `MC_SEND_CONFIG_SET` | the configuration set from `--send-config-set` |
| `MC_AWS_SEND_ROLE_ARN` | `arn:aws:iam::<account>:role/mail-console-send` |
| `MC_SEND_DEFAULT_REPLY_TO` | optional: where replies go when an address has no Reply-To of its own |
| `MC_SEND_KEEP_BODY_DAYS` | optional: days to keep the text of what Compose sent so admins can read it later (default `0`: keep nothing) |
| `MC_SEND_MAX_RECIPIENTS`, `MC_SEND_PER_USER_PER_HOUR`, `_PER_USER_PER_DAY`, `MC_SEND_PER_DAY` | optional limits (defaults 10, 20, 100, 300 recipients) |

In the console, a security admin switches each address on under **Compose, Sending addresses** (they start off), and can set a
display name and Reply-To. Run **Setup check, Test write roles** to prove the send role can be assumed (it sends nothing).
To allow a new address: add it to `--send-from`, re-render and run the last two `put-role-policy` commands again, and add it to
`MC_SEND_FROM_ADDRESSES`. The console cannot widen the AWS policy, so a new address in the environment alone does not work.

## 9. DMARC reports by mail (optional)

Off by default. Mailbox providers e-mail a DMARC aggregate report to the address in your DMARC record once a day. With this
section the console receives them itself, so nobody has to download and upload them. It needs a region where SES can **receive**
mail (`ap-south-1` is one; check the SES documentation for yours) and a subdomain used only for reports, for example
`reports.example.com`, so your normal mailboxes are untouched.

```
provider -> reports.example.com (MX) -> SES receiving -> S3 (raw mail, deleted after 14 days) + SNS -> SQS (+ dead-letter queue) -> console worker
```

What is checked, in this order, before a report is counted: the notification comes from the allowed topic and is for exactly the
reports address; SES's virus check passed and the spam check did not fail; **SES's DMARC check of the sender passed** (so the
mail really came from the domain in its From header); the object is in the configured bucket and folder; the message is under
5 MB, has at most 10 parts and 3 attachments; and each attachment passes the same strict validation as a manual upload. Mail
that fails a check is recorded with its reason on the DMARC page and dropped.

**Who sent it matters as much as whether it is genuine mail.** A passing DMARC check proves who *sent* the mail, not that the
sender is a real reporting provider: anyone who controls a domain with DMARC set up can mail you a report that claims to be
from "google.com". So the sender, read from the header From with a strict parser (exactly one plain mailbox, never an address
found inside a display name, never the envelope sender), is stored with every report and is part of its uniqueness key (a forged
report can never take the slot of the genuine one). List the providers you recognise in `MC_DMARC_SENDERS`: their reports are
*verified*. An entry is either a **domain** (exactly that domain; its subdomains are *not* trusted, list them if you need them) or
a **full address** (exactly that address). Where a domain is shared by many people (a consumer mail domain, or any domain that gives
out addresses or subdomains), list the provider's exact address and never the domain. An address entry narrows trust to one mailbox, but be clear about what it
rests on: SES's DMARC check proves the *domain* of the From address, not the mailbox, so the entry is only as strong as that
domain's own control over who may use which From address. It does not make a domain you do not operate trustworthy. Reports from any other authenticated sender are
still stored and counted, but labelled *unverified* (like uploads), and a verified copy of the same report replaces them. The DMARC
page lists the unlisted senders it has seen so you can decide which to add. The console does not compare the sender with the
organisation named inside the report, because providers name themselves inconsistently.

**Allowances** are kept in separate pools, so strangers cannot use up the allowance of the providers you list: mail that failed the
checks (its From is unauthenticated, so it is never counted against anyone), listed providers (`MC_DMARC_MAX_PER_DAY`, 300), other
authenticated senders (`MC_DMARC_UNLISTED_MAX_PER_DAY`, 200) and each sender address on its own (`MC_DMARC_MAX_PER_SENDER`, 50), each over a
rolling day. Mail beyond an allowance is **not deleted**: it stays on the queue and ends in the dead-letter queue, where it can be
recovered, and one line a day in the log says it happened.

Render the extra files (every option is validated; names are examples):

```bash
python3 aws/render.py ... \
  --dmarc-queue-arn arn:aws:sqs:ap-south-1:<account>:mail-console-dmarc \
  --dmarc-topic-arn arn:aws:sns:ap-south-1:<account>:mail-console-dmarc \
  --dmarc-bucket example-mail-console-dmarc
```

The topic and queue ARNs must be the ones created in 9.2 (they follow from the names you choose, so you can render first).

**9.1 Bucket** (private, encrypted with the bucket's own key, mail deleted after 14 days). Do **not** turn on SES "message
encryption": it encrypts on the client side and the console could not read the mail. Do not turn on S3 Object Lock.

```bash
B=example-mail-console-dmarc; R=ap-south-1
aws s3api create-bucket --bucket "$B" --region "$R" --create-bucket-configuration LocationConstraint="$R"
aws s3api put-public-access-block --bucket "$B" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$B" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-lifecycle-configuration --bucket "$B" --lifecycle-configuration '{"Rules":[{"ID":"expire-report-mail","Status":"Enabled","Filter":{"Prefix":"dmarc/"},"Expiration":{"Days":14},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":2}}]}'
aws s3api put-bucket-policy --bucket "$B" --policy file://aws-rendered/dmarc-bucket-policy.json
```

**9.2 Topic, queue and dead-letter queue** (same pattern as step 1):

```bash
DT=$(aws sns create-topic --name mail-console-dmarc --query TopicArn --output text)
aws sns set-topic-attributes --topic-arn "$DT" --attribute-name Policy --attribute-value file://aws-rendered/dmarc-topic-policy.json
DLQ_URL=$(aws sqs create-queue --queue-name mail-console-dmarc-dlq --attributes MessageRetentionPeriod=1209600,SqsManagedSseEnabled=true --query QueueUrl --output text)
DLQ_ARN=$(aws sqs get-queue-attributes --queue-url "$DLQ_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)
cat > dmarc-queue-create.json <<JSON
{"VisibilityTimeout":"120","MessageRetentionPeriod":"345600","SqsManagedSseEnabled":"true",
 "RedrivePolicy":"{\"deadLetterTargetArn\":\"$DLQ_ARN\",\"maxReceiveCount\":\"5\"}"}
JSON
DQ_URL=$(aws sqs create-queue --queue-name mail-console-dmarc --attributes file://dmarc-queue-create.json --query QueueUrl --output text)
aws sqs set-queue-attributes --queue-url "$DQ_URL" --attributes file://aws-rendered/dmarc-queue-attributes.json
DQ_ARN=$(aws sqs get-queue-attributes --queue-url "$DQ_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)
aws sns subscribe --topic-arn "$DT" --protocol sqs --notification-endpoint "$DQ_ARN"
```

**9.3 Let the console role read them.** This adds one statement to the permissions boundary (read objects in that one bucket
folder) and gives the app role two statements (consume that one queue, read that one folder). It cannot write or delete in S3,
list the bucket, or send mail. Without `s3:ListBucket`, S3 answers "access denied" rather than "not found" for a missing object,
so a notification for mail that has already expired is retried and then ends in the dead-letter queue, which is harmless.

```bash
aws iam create-policy-version --policy-arn "$BOUNDARY_ARN" --policy-document file://aws-rendered/permissions-boundary-extended.json --set-as-default
aws iam put-role-policy --role-name mail-console-app --policy-name dmarc-inbound --policy-document file://aws-rendered/dmarc-inbound.json
```

**9.4 Receive the mail.** One receipt rule, scanning on, for exactly the reports address. SES allows **one active rule set per
region**: if you already have one, add this rule to it instead and pass its name as `--dmarc-rule-set` when rendering.

```bash
cat > dmarc-rule.json <<JSON
{"Name":"dmarc-reports","Enabled":true,"TlsPolicy":"Optional","ScanEnabled":true,"Recipients":["dmarc@reports.example.com"],
 "Actions":[{"S3Action":{"BucketName":"$B","ObjectKeyPrefix":"dmarc/","TopicArn":"$DT"}}]}
JSON
aws ses create-receipt-rule-set --rule-set-name mail-console-dmarc
aws ses create-receipt-rule --rule-set-name mail-console-dmarc --rule file://dmarc-rule.json
aws ses set-active-receipt-rule-set --rule-set-name mail-console-dmarc
```

**9.5 DNS** (at your DNS host):

| Name | Type | Value |
|---|---|---|
| `reports.example.com` | MX | `10 inbound-smtp.ap-south-1.amazonaws.com` (use your region's endpoint) |
| `_dmarc.example.com` | TXT | your current record with the new address added to `rua`, for example `v=DMARC1; p=none; rua=mailto:dmarc@reports.example.com,mailto:<your old address>` |

Keep the old address in `rua` for a couple of weeks, then drop it. A report that arrives both ways is counted once. A provider that
refuses to send to the subdomain may need the external-destination record `example.com._report._dmarc.reports.example.com`
TXT `v=DMARC1`.

**9.6 Run the worker.** Set these in the console's environment (the console refuses to start if they are wrong), then start a
second worker process:

| Variable | Value |
|---|---|
| `MC_SQS_DMARC_QUEUE_URL` | `$DQ_URL` (setting this switches the feature on) |
| `MC_DMARC_TOPIC_ARNS` | `$DT` (comma separated) |
| `MC_DMARC_ADDRESS` | `dmarc@reports.example.com` |
| `MC_DMARC_BUCKET` | `$B` |
| `MC_DMARC_KEY_PREFIX` | optional, default `dmarc/` |
| `MC_DMARC_SENDERS` | the reporting providers you trust, comma separated: exact domains or exact addresses, no wildcards and no automatic subdomains (for example `google.com,noreply-dmarc-support@example.net`). Empty means every mailed report is labelled unverified |
| `MC_DMARC_MAX_PER_DAY`, `MC_DMARC_UNLISTED_MAX_PER_DAY`, `MC_DMARC_MAX_PER_SENDER` | optional daily allowances, defaults `300`, `200`, `50` |
| `MC_WORKER_HEARTBEAT_FILE` | give it a different path from the event worker's if both share a volume |

| Process | Command |
|---|---|
| DMARC worker | `python manage.py ingest_dmarc_mail` (always, restart on exit) |

The **Setup check** then has a "DMARC collection" group (queue reachable, dead-letter queue, providers listed, last report received), the DMARC page
has a "Collection by mail" card, and an alert opens if reports that used to arrive stop for 3 days.

## 10. Read the text of mail sent by other applications (optional)

Off by default. SES publishes no message content in its events, so the console normally shows what happened to a message but never what it
said. SES can, however, copy every message sent through a configuration set into an **SES Mail Manager archive**. With the steps below an
admin can open the **Body** tab of a message in Sent mail and read that copy, with a reason and a passkey check, and every opening is audited.

What to know before you switch it on:

- **The archive holds the full text of everything sent through the configuration sets you attach it to**, including sign-in, invitation and
  password-reset links and one-time codes. Attach it only to sets whose mail you are prepared to keep that way.
- **AWS's shortest retention is three months.** Archives cannot delete single messages; they expire everything after the retention period.
  The console shows archived mail for `MC_ARCHIVE_VIEW_DAYS` (default 30) after it was sent and refuses to open anything older, but that
  limits what the console shows, not what AWS stores. Anyone with permission to read the archive in AWS can read all of it.
- **The console redacts what it shows:** HTML is turned into plain text (link targets are dropped), query strings and long opaque path segments
  in links are masked, and one-time codes and keys are masked. Redaction is best-effort: it removes what it recognises.
- **Mail categories can restrict it.** A message belongs to a mail category (from its `mc-category` tag, or its configuration set). If a `MailCategory` row
  with that name exists, the console follows it: `store_body` off blocks reading the text, `body_retention_days` can shorten the window below
  `MC_ARCHIVE_VIEW_DAYS` (never extend it), and `redaction_rules` (regular expressions) add to the redaction. Messages with no such row follow the
  global settings. There is no screen for categories yet; create the rows with `manage.py shell`.
- **Encrypt the archive with its own KMS key** and keep the key policy narrow (below). Nothing from the archive is stored in the console's
  database.
- **Which mail is copied:** SES documents archiving for mail sent through the `SendEmail` and `SendBulkEmail` API operations. Check that mail sent
  through the SMTP interface is copied too (send one and look for it) before relying on it for an application that sends over SMTP. A
  message with no copy shows "No archived copy of this message was found".
- **Cost:** Mail Manager archiving is billed by volume and retention (see the SES pricing page); at a few messages a day it is small.

**10.1 The key.** Put this in a file (replace the account id) and create the key:

```bash
cat > archive-kms-policy.json <<JSON
{"Version":"2012-10-17","Id":"mail-archive-key","Statement":[
 {"Sid":"EnableIamPoliciesInThisAccount","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account>:root"},"Action":"kms:*","Resource":"*"},
 {"Sid":"AllowSesToEncryptAndDecryptTheArchive","Effect":"Allow","Principal":{"Service":"ses.amazonaws.com"},
  "Action":["kms:GenerateDataKey","kms:Decrypt","kms:DescribeKey"],"Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":"<account>"}}}]}
JSON
KEY_ARN=$(aws kms create-key --region ap-south-1 --description "Encrypts the archive of sent mail" --policy file://archive-kms-policy.json --query KeyMetadata.Arn --output text)
aws kms create-alias --region ap-south-1 --alias-name alias/mail-archive --target-key-id "$KEY_ARN"
```

**10.2 The archive** (three months is the minimum retention):

```bash
ARCHIVE_ID=$(aws mailmanager create-archive --region ap-south-1 --archive-name sent-mail --retention RetentionPeriod=THREE_MONTHS --kms-key-arn "$KEY_ARN" --query ArchiveId --output text)
ARCHIVE_ARN=$(aws mailmanager get-archive --region ap-south-1 --archive-id "$ARCHIVE_ID" --query ArchiveArn --output text)
```

**10.3 Attach it to the configuration sets whose mail you want to read** (repeat per set; SES then copies each new message sent through it):

```bash
aws sesv2 put-configuration-set-archiving-options --region ap-south-1 --configuration-set-name my-first-configuration-set --archive-arn "$ARCHIVE_ARN"
```

**10.4 Let the console role read it.** Render with the archive options (both are required, and both must be in `--region`). This adds one
statement to the permissions boundary (decrypt with that one key, only through SES) and gives the app role two statements (read that one
archive, decrypt with that one key). It cannot create, change or delete anything, and still cannot send mail:

```bash
python3 aws/render.py ... --archive-arn "$ARCHIVE_ARN" --archive-kms-key-arn "$KEY_ARN"
aws iam create-policy-version --policy-arn "$BOUNDARY_ARN" --policy-document file://aws-rendered/permissions-boundary-extended.json --set-as-default
aws iam put-role-policy --role-name mail-console-app --policy-name archive-read --policy-document file://aws-rendered/archive-read.json
```

If you also use section 9, `permissions-boundary-extended.json` carries both additions: create ONE new boundary version from it.

**10.5 The console.** Set `MC_MAIL_ARCHIVE_ID` to `$ARCHIVE_ID` (the id, like `a-abc123...`) and optionally `MC_ARCHIVE_VIEW_DAYS`, then restart the web
process. The **Setup check** gets a "Mail archive" group. A search of the archive takes a few seconds, so opening a message's text pauses
briefly.

## 11. Keep a permanent copy of archived mail in a Google Workspace mailbox (optional)

Off by default. Section 10's archive keeps mail for at most its retention period and is read one message at a time. This adds a worker that
copies every message that appears in the archive into a mailbox you already have, so you can search it like any other mail and keep it for
as long as you keep the mailbox.

```
SES archive (section 10) --original message--> sync worker --Gmail API: insert only--> a Google Workspace mailbox
```

How it behaves:

- **Nothing is sent.** The worker *inserts* each message (like IMAP APPEND): it keeps its original date, sender and recipients, skips spam
  classification, and does not run the mailbox's filters. Each copy carries two labels and nothing else: `<root>` and `<root>/<Sender>` (for example
  `Sent via SES/Cloud`). With no Inbox label a copy never appears in the Inbox, and with no Unread label it adds no unread count. Find copies under the
  label, in All Mail, or by searching (`from:cloud@example.com`).
- **Everything is kept, unredacted.** The mailbox holds the full original, including sign-in links and one-time codes. Treat it like a vault: use a
  mailbox only you read, and set a Google Vault retention rule if you want to stop anyone deleting copies.
- **Only mail that reaches the archive** (section 10) is copied, and only from when the archive was attached to a configuration set.
- **The credential can only insert mail and manage labels.** It cannot read, search or delete anything in the mailbox.
- **Safe to repeat.** A record per message (metadata only, never the content) stops anything being imported twice; failures are retried a limited number
  of times; the newest hour is rescanned each pass; a busy moment is split by time and then by sender, and if it still cannot be completed the Setup check
  and an alert say so.

**11.1 The AWS permission.** The console role needs to fetch the original message from the archive. This is one more action in `archive-read.json`
(`ses:GetArchiveMessage`): re-render with the archive options (section 10.4) and run the `put-role-policy` command again.

**11.2 The Google credential**, for ONE mailbox. Choose A or B.

*A. A service account with domain-wide delegation* (recommended)

1. In the Google Cloud console, create or pick a project and enable the **Gmail API**.
2. **IAM and admin, Service accounts**: create an account (no roles needed) and create a **JSON key** for it. Newer organisations block creating
   service account keys by default (the policy `iam.disableServiceAccountKeyCreation`); an organisation admin can allow it for this one project.
3. Copy the service account's numeric **Client ID** (shown in its details).
4. In **Google Admin, Security, Access and data control, API controls, Manage domain-wide delegation**, add that Client ID with exactly these two scopes:
   `https://www.googleapis.com/auth/gmail.insert,https://www.googleapis.com/auth/gmail.labels`
5. Put the JSON key on the server as a read-only secret file (never in the repository, an image or a chat).

*B. An OAuth refresh token* (if keys are blocked): create an OAuth client in the same project (an "internal" app), and sign in once **as the mailbox**
to authorise the same two scopes, which gives a refresh token. Keep the client id, secret and token as secrets.

**11.3 The worker.** Set these in the console's environment (it refuses to start if they are wrong):

| Variable | Value |
|---|---|
| `MC_ARCHIVE_SYNC_MAILBOX` | the mailbox that receives the copies (setting this switches the feature on); `MC_MAIL_ARCHIVE_ID` must be set too |
| `MC_GOOGLE_SERVICE_ACCOUNT_FILE` | path of the JSON key inside the container (option A) |
| `MC_GOOGLE_OAUTH_CLIENT_ID`, `MC_GOOGLE_OAUTH_CLIENT_SECRET`, `MC_GOOGLE_OAUTH_REFRESH_TOKEN` | all three, instead of the file (option B) |
| `MC_ARCHIVE_SYNC_LABEL_ROOT` | optional, default `Sent via SES`; not a system label name |
| `MC_ARCHIVE_SYNC_INTERVAL` | optional seconds between passes, default 300 (60 to 86400) |

Then run it as its own process, and run migrations first (a new table records what was copied):

| Process | Command |
|---|---|
| Mailbox copy | `python manage.py sync_archive_to_mailbox` (always, restart on exit) |

In a compose file, mount the key read-only into that container, for example `volumes: ["./secrets/google-key.json:/run/secrets/google-key.json:ro"]`, and point
`MC_GOOGLE_SERVICE_ACCOUNT_FILE` at it. The **Setup check** gets a "Mailbox copy" group (does the credential work, is the sync running, did anything fail or
stay incomplete), and alerts open if the sync stops or a message cannot be copied. The first pass copies everything already in the archive.

## Changing or removing things
Remove the SES event destination before deleting the topic, and delete the subscription before the queue. Delete the
roles in the reverse order of creation (write roles, then the app role, then the boundary policy). Do not delete the
configuration set. Because these steps are destructive, they are described here rather than given as a block to paste.
