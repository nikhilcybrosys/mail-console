# Mail Console: infrastructure (Terraform)

IaC for the secure SES console described in `plans/Claude-Code-SES-Mail-Console-Plan.md`
(sections 4, 5, 7, 9) and updated by `docs/phase0/verify-findings.md`. Provider
`hashicorp/aws ~> 6.0` (validated with 6.69.1), Terraform `>= 1.9`.
**Nothing here has ever been planned or applied against AWS.** A human applies it, staging first.

## Layout

```
envs/staging, envs/production   same main.tf; differ only in variables.tf defaults + tfvars
modules/
  kms                 3 CMKs (events, data, audit), rotation, service-principal key policies
  network             VPC, private subnets, ALB-only public subnets, endpoints, flow logs, optional NAT
  storage             audit bucket (Object Lock), content bucket, GuardDuty malware plan
  ses_pipeline        config sets, SNS->SQS(+DLQ), Firehose->raw-events S3, optional identities
  mailmanager_inbound ingress point, traffic policy, rule set, inbound + outbound archives
  secrets             Secrets Manager SHELLS (values loaded by hand)
  rds                 PostgreSQL 16, forced TLS, PITR, RDS-managed master secret
  iam_roles           console-web / worker / write-ops / write-security / ecs-execution + console-boundary
  ecs                 cluster, ECR, web + worker services, scheduled sync task, autoscaling
  alb_waf             ALB, WAFv2, console + mailview host rules, access logs
  observability       alarms, alerts topic, CloudTrail, EventBridge SES-change rules, GuardDuty, Access Analyzer, Config
  _secure_bucket, _sns_to_sqs   internal building blocks
scp/                  suggested SCPs (documents only, NOT applied)
iam_simulation_tests/ commands that prove the roles cannot send mail
COST.md               rough monthly cost per component
```

## Apply order (human, per environment, staging first)

0. **By hand, once:** create the Terraform state bucket (versioned, SSE-KMS, BPA) and DynamoDB lock
   table in the new account; put their names in `envs/*/backend.tf`. Create a Terraform admin role (no IAM users, no static keys).
1. Request/validate the **ACM certificates** (console domain, and the mailview domain) and note the ARNs.
2. `cp terraform.tfvars.example terraform.tfvars`, fill it in (no secrets in it).
3. `terraform init && terraform plan` and **read the plan**. ECS services need a real image, so apply in two steps:
   first `terraform apply -target=module.ecs.aws_ecr_repository.this` plus the foundation modules
   (`-target=module.kms -target=module.network -target=module.storage -target=module.mailmanager -target=module.ses_pipeline -target=module.secrets -target=module.rds -target=module.alb_waf -target=module.iam_roles -target=module.observability`),
   push the first image to the new ECR repo (`ecr_repository_url` output), set `image_tag`, then run a plain `terraform apply`.
4. **Load the secret values by hand** (see below). Run the DB migration; create the `mc_app` DB role (INSERT-only on `audit_log`).
5. **DNS by hand** (Terraform manages no DNS): CNAME/ALIAS `domain_name` and `mailview_domain_name` to `alb_dns_name`;
   MX `inbound.<domain>` per the `inbound_mx_instructions` output.
6. Run `iam_simulation_tests/README.md`. Run the staging mailbox-simulator matrix (plan section 11).
7. Only after staging is accepted: production, then (Phase 7) point identities at `mc-default` one at a time.

## Needs human input (cannot be generated)

- ACM certificate ARNs; the three domains (console, mailview on a separate registrable domain, inbound sub-domain).
- **Secrets, put in out of band** (never in tfvars, state, repo or chat):
  `aws secretsmanager put-secret-value --secret-id <prefix>/oidc-client --secret-string file://oidc.json` (then delete the file); same for
  `django-secret-key`, `app-db` (`{"username":"mc_app","password":"..."}`) and `alerts-webhook`.
  The RDS master password is generated and rotated by RDS itself.
- Alert destinations: `alert_email_addresses` (confirm the SNS e-mail), PagerDuty via `alert_https_endpoints`. Slack: AWS Chatbot is console-only (see Known gaps).
- `trusted_admin_principal_arns`: the role that runs `terraform apply`, otherwise your own SES changes trigger the "non-console principal" alert.

## Existing SES identities: import, do not recreate

`manage_identities = false` (default) means Terraform never touches identities, so existing senders are safe.
To manage one (after the staging default-config-set test passes):

```hcl
manage_identities = true
identities = { "example.com" = { default_configuration_set = "mc-default", mail_from_domain = "mail.example.com" } }
```
```bash
terraform import 'module.ses_pipeline.aws_sesv2_email_identity.this["example.com"]' example.com
terraform import 'module.ses_pipeline.aws_sesv2_email_identity_mail_from_attributes.this["example.com"]' example.com
terraform plan   # must show only the configuration_set_name change; DKIM is ignore_changes
```
Setting a default config set changes how that identity's mail is tracked immediately. Do it one identity at a time.
Config sets are `prevent_destroy`: deleting a set that is an identity's default breaks every send from that identity.

## Decisions baked in

- **SNS->SQS `raw_message_delivery = false`**: keep the SNS envelope so the worker can verify `TopicArn`/`MessageId`/`SignatureVersion` and dedupe. Cost: ~0.5 KB/message.
- **Queue policy** allows only `sns.amazonaws.com` with `aws:SourceArn` = the topic. Topic policy allows only SES for our config-set ARNs.
- **Bucket policies**: TLS 1.2+ only; if a request names an encryption header it must be `aws:kms` with the bucket's key (a request with no header is accepted and encrypted by bucket default, which GuardDuty/SES service writes need). ALB log bucket is SSE-S3 (ALB cannot write to SSE-KMS).
- **Write roles** require `sts:SourceIdentity` = `*@example.com` in the trust policy AND on every allow (`aws:SourceIdentity`), `max_session_duration` 3600 (IAM minimum; the app asks for 900 s).
- **Boundary** `console-boundary` Denies all seven `ses:Send*` actions (+ `ses:Send*`), SES outside `ses_regions`, and IAM self-escalation, on every console role.
- The sync task runs as the worker role (SES read subset). The web role also gets SES read actions via `Resource "*"`; the Service Authorization Reference lists no resource scoping for most of them.

## Known gaps (not faked)

1. **Archive on config sets** is not in the Terraform provider (`aws_sesv2_configuration_set` has no archiving option). `mc-archive` is created with `aws_cloudformation_stack` (`AWS::SES::ConfigurationSet.ArchivingOptions`); its event destinations are still native resources. No `aws_mailmanager_address_list` exists either (none is used yet; use CloudFormation if needed).
2. **Archive retention minimum is THREE_MONTHS.** The plan's 30-day outbound-body retention cannot be enforced by the archive; enforce it in the app (redaction/expiry). Inbound default is also THREE_MONTHS.
3. **Which account holds SES?** Findings 9/10: the SES event destination, SNS topic policy, KMS key, Firehose role and the outbound archive must be in the SENDING account, and the archive is probably usable only there. This code puts everything in ONE account (the new console account). If your applications keep sending from a different AWS account, instantiate `modules/ses_pipeline` + the archive in that account with a provider alias and add a cross-account queue policy/role-assumption. Not built: **Decision D2**.
4. **OIDC provider needs internet egress** (no PrivateLink). Module default `enable_nat=false` per brief; both env defaults set it `true`, otherwise nobody can log in. An allow-listing proxy / Network Firewall is the hardening upgrade (not built). The Mail Manager API's PrivateLink availability is unverified; if archive search from private subnets fails, NAT covers it.
5. **Cross-region RDS snapshot copy / DR** needs a second provider region and KMS key: not created. Add `aws_db_instance_automated_backups_replication` once the DR region is chosen.
6. **Slack alerts**: SNS cannot post to Slack directly; AWS Chatbot setup is console-only. PagerDuty works through `alert_https_endpoints`.
7. **Attachments**: Mail Manager `write_to_s3` stores the whole raw message, not extracted attachments. GuardDuty scans objects under `inbound/` and `attachments/`; the app must check the scan tag before serving.
8. **Still TODO-VERIFY** (staging): whether SNS service KMS calls carry `aws:SourceArn` (key policy uses SourceAccount only for SNS; Phase 0 test #7); whether SES import jobs read S3 with caller credentials or the service principal (bucket-policy statement and `imports/` grants kept either way); whether the SES->Firehose role needs KMS permissions; that the interface-endpoint service names `email` and `monitoring` exist in ap-south-1 (the endpoint list is variable-driven); that CloudTrail delivery works with the trail bucket's encryption-header rule (key-id check is off there); whether `CreateConfigurationSetEventDestination` needs `iam:PassRole` for the Firehose role (commented in `iam_roles`).
9. No S3 server access logging, no VPC endpoint policies, no pgaudit (needs a reboot-time parameter), no Shield Advanced, no Security Hub. Add if the compliance review asks.
10. **Object Lock COMPLIANCE is irreversible.** Staging defaults to GOVERNANCE 30 days; production is COMPLIANCE (7 y audit, 396 d raw events). `prevent_destroy` on config sets and identities also blocks `terraform destroy`: remove it deliberately.
11. Event/DLQ redrive, Secrets Manager rotation for non-RDS secrets, and WAF managed-rule tuning (e.g. `SizeRestrictions_BODY` for template editing) are operational follow-ups.

## Decisions to make before applying

- **D1** NAT (about USD 45/month) vs egress proxy for OIDC provider.
- **D2** Which account owns SES sending/config sets/events (gap 3).
- **D3** Confirm COMPLIANCE lock for audit (7 y) and raw events (13 mo) in production.
- **D4** Interface-endpoint set and AZ count (COST.md: about USD 170/month for nine endpoints in two AZs).
- **D5** Enable Mail Manager inbound now (about USD 50/month) or at Phase 5.
- **D6** Accept THREE_MONTHS archive minimum, or skip outbound body archive and store bodies in the app.

## Provider lock files

`envs/*/.terraform.lock.hcl` currently hold the darwin_arm64 hash only (the registry was unreachable for multi-platform locking). Before CI/Linux use:
`terraform providers lock -platform=linux_amd64 -platform=linux_arm64 -platform=darwin_amd64 -platform=darwin_arm64`.
