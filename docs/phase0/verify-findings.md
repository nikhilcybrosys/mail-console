# Phase 0 [VERIFY] findings: Mail Console (SES)

> Note: this research was done while the project still planned to ship Terraform. That plan was dropped in favour of plain AWS CLI steps and
> IAM policy files (`aws/`), so the Terraform-specific parts below (provider coverage, `terraform destroy` warnings) are background only.

Date: 2026-10-22. Method: official AWS documentation only (docs.aws.amazon.com, aws.amazon.com), no AWS credentials, no AWS API calls, no secrets read. Where a rendered page was JS-only, the machine-readable AWS sources behind it were used (AWS Service Reference JSON, AWS price-list JSON). Terraform facts come from the provider docs at tag v6.69.1 and the Terraform registry API.

## Summary

| # | Item | Status | Answer (one line) |
|---|---|---|---|
| 1 | GetMessageInsights retention / VDM / TPS | TPS RESOLVED; retention and VDM UNRESOLVED | 1 call/sec documented; 30 days documented only for the VDM Messages table; VDM presumed required; simulator and multi-recipient mail may be excluded |
| 2 | Control-plane TPS | PARTIAL | BatchGetMetricData 16 rps (160 queries/s); GetMessageInsights and CreateExportJob 1 rps; the other five have no per-op limit, generic quota is 1 rps for all non-send actions |
| 3 | IAM actions, ARNs, condition keys | RESOLVED | `ses:` prefix covers v2 and Mail Manager; full table below; StartArchiveSearch is Write level; 7 send actions exist (plan withholds 3) |
| 4 | Mail Manager / receiving regions, outbound archive | RESOLVED (3 sub-points UNRESOLVED) | ap-south-1 supports BOTH Mail Manager (since 2025-01) and classic receiving; config-set archive works for SendEmail/SendBulkEmail; SMTP path, cross-account archive and processing fee untested |
| 5 | Suppression export / page size | RESOLVED (max PageSize UNRESOLVED) | No export API or job exists (CreateExportJob = METRICS_DATA / MESSAGE_INSIGHTS only); mirror by pagination; PageSize max not documented, AWS blog uses 1000 |
| 6 | Easy DKIM rotation | RESOLVED (schedule UNRESOLVED) | SES rotates Easy DKIM keys automatically with no customer steps or rotate API (only key length can be changed, once/day); manual rotation needs BYODKIM; interval not documented; empty TXT behind CNAMEs is normal |
| 7 | SNS / SQS / Firehose / GuardDuty pricing | RESOLVED | Mumbai: SNS $0.50/M, SQS $0.40/M (1M free), Firehose $0.034/GB (5 KB rounding), GuardDuty S3 $0.1125/GB + $0.271/1k objects; us-east-1 $0.50/M, $0.40/M, $0.029/GB, $0.09/GB + $0.215/1k; pipeline about $2-5/month at 1M mails |
| 8 | SNS-KMS, SQS, Firehose policies | RESOLVED (SourceArn on KMS key policy UNRESOLVED) | SES supports SSE-KMS topics: CMK key policy grants ses.amazonaws.com kms:GenerateDataKey* + kms:Decrypt; topic policy ses.amazonaws.com sns:Publish with SourceAccount/SourceArn=config set; queue policy sns.amazonaws.com sqs:SendMessage with SourceArn=topic; Firehose role trusts ses.amazonaws.com |
| 9 | Default configuration set behaviour | RESOLVED (SMTP point UNRESOLVED) | Default applies to all sends from a verified identity unless the request names a set; address overrides domain; docs silent on SMTP specifically; deleting the set breaks sending (bad request) |
| 10 | Terraform / CloudFormation coverage | RESOLVED | Provider 6.69.1 has native sesv2 config set, all event destinations, identity (+feedback, mail_from, policy), account VDM, and aws_mailmanager_{archive,ingress_point,rule_set,traffic_policy,relay}; NOT address_list and NOT config-set archiving_options (both available in CloudFormation) |

(Sections below are filled in item by item.)

## 1. GetMessageInsights: retention, VDM requirement, TPS

**Status: TPS RESOLVED. Retention and VDM requirement UNRESOLVED for the API itself (documented only for the VDM Messages table).**

- TPS. API ref: "You can execute this operation no more than once per second." https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_GetMessageInsights.html
- Retention. The API reference gives no window. The VDM dashboard guide says "you can filter on messages you've sent within the last 30 days" and "The table can load up to 100 messages." The AWS blog says "customers can see the delivery transaction status and details for every email they have sent in the last 30 days." The CLI section of the dashboard guide says `GetMessageInsights` returns "the same data used in the Message info sidebar" of the Messages table, so 30 days is the best-supported figure but is inferred for the API.
  https://docs.aws.amazon.com/ses/latest/dg/vdm-dashboard.html , https://aws.amazon.com/blogs/messaging-and-targeting/improve-email-delivery-rates-with-email-delivery-and-engagement-history-for-every-email/
- VDM requirement. No sentence states the API fails without VDM. The blog: "if you have Virtual Deliverability Manager enabled, just open ... the 'Messages' tab"; the dashboard guide: "Dashboard will not be visible if you haven't enabled Virtual Deliverability Manager". Treat VDM as required.
- Caveats from the same guide (about VDM metrics, may also affect lookups): "Virtual Deliverability Manager only tracks metrics from emails that have one recipient" and "Emails sent to the SES mailbox simulator are not counted in any of the Virtual Deliverability Manager dashboard metrics." The plan's simulator test matrix may therefore not appear in GetMessageInsights.
- Related: `CreateExportJob` with `MessageInsightsDataSource` exports message search results ("If your filtered search returns more than 10,000 messages, the 10,000 messages in the API's result set are a random sample"), 1 call/sec. Useful for gap-fill, not a complete source.
- Cost: VDM "Per email fee: $0.07/1,000 emails (0-10M emails per month)" plus "Queries: $0.0005/1,000 queries (first 5K queries/month are free)". Whether GetMessageInsights counts as a "query" is not stated. https://aws.amazon.com/ses/pricing/

**Safe read-only test:** in an account with VDM enabled, call `GetMessageInsights` for (a) a message id sent ~25 days ago, (b) one ~35 days ago, (c) a mailbox-simulator message, (d) a multi-recipient message; then repeat (a) in an account with VDM disabled. Record NotFound/BadRequest behaviour.

## 2. Control-plane TPS for the calls we will use

**Status: PARTIALLY RESOLVED. BatchGetMetricData and GetMessageInsights have explicit limits. The other five have no per-operation limit in the API reference; only a generic 1 rps quota that is not clearly scoped to v2.**

| Operation | Documented limit | Source |
|---|---|---|
| BatchGetMetricData | "no more than 16 times per second, and with at most 160 queries from the batches per second (cumulative)" | API_BatchGetMetricData |
| GetMessageInsights | "no more than once per second" | API_GetMessageInsights |
| CreateExportJob | "no more than once per second" | API_CreateExportJob |
| ListSuppressedDestinations | none stated | API_ListSuppressedDestinations |
| GetSuppressedDestination | none stated | API_GetSuppressedDestination |
| GetEmailIdentity | none stated | API_GetEmailIdentity |
| GetAccount | none stated | API_GetAccount |
| ListEmailIdentities | none stated | API_ListEmailIdentities |

Generic quota (SES quotas page, "SES API sending quotas"): "All actions (except for `SendEmail`, `SendRawEmail`, and `SendTemplatedEmail`) are throttled at one request per second." Adjustable: No. https://docs.aws.amazon.com/ses/latest/dg/quotas.html . The AWS General Reference quota table (https://docs.aws.amazon.com/general/latest/gr/ses.html) lists only config set count, sending quota, sending rate and tenant count, no API rate. The page does not say whether the 1 rps is per action or shared across all actions, or whether it covers the v2 control plane (v2 operation pages exist with their own limits, so it may be v1-centric).

**Safe read-only test:** from one host, loop `GetAccount` at 3 rps for 30 s and count `TooManyRequestsException`; repeat interleaving `GetAccount` and `ListEmailIdentities` at 1 rps each to see whether the bucket is per action or shared. Do the same for `ListSuppressedDestinations`. Reads only.

**Design default until tested:** one token bucket of 1 rps per (account, region) for all control-plane calls, 16 rps for BatchGetMetricData.

## 3. IAM actions, resource ARNs, condition keys

**Status: RESOLVED.**

Source: AWS Service Reference JSON for service `ses` (v1.5, 233 actions, 20 resource types), the machine-readable form of the Service Authorization Reference (https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonses.html and .../list_amazonsimpleemailservicev2.html, which did not render for the fetch tool). Retrieved from https://servicereference.us-east-1.amazonaws.com/v1/ses/ses.json (documented at https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html).

**Prefix.** Yes, `ses:` is the prefix for v2 operations. There is one service, `ses`, covering SES v1, SES v2 and Mail Manager; v2 operations such as `GetAccount`, `BatchGetMetricData`, `PutSuppressedDestination` and the `MailManager` archive/ingress operations are all `ses:<OperationName>`. The developer guide: "You can set the `Action` element to any SES API action by prefixing the API name with the lowercase string `ses:`." https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html . The key `ses:ApiVersion` separates v1 from v2: the guide's example uses `"ses:ApiVersion" : "2"` ("Allowing Access to only SES API version 2"), and "The SES SMTP interface uses SES API version 2 of `ses:SendRawEmail`."

Notes that matter for the plan:
- Account-level calls (`GetAccount`, `ListEmailIdentities`, `ListConfigurationSets`, `GetMessageInsights`, `GetEmailAddressInsights`, `GetBlacklistReports`, templates list) have no resource type: use `Resource: "*"`.
- `ListSuppressedDestinations`, `GetSuppressedDestination`, `PutSuppressedDestination`, `DeleteSuppressedDestination` list only the `tenant` resource type (tenant-level suppression, added 2026-06). For the account-level list there is no resource to scope to, so use `*`; this is inferred, not stated. Verify with the IAM policy simulator at build time.
- `ses:StartArchiveSearch`, `StopArchiveSearch`, `StartArchiveExport` are classified Write, not Read. A read role built from "read-only" managed policies will not include them; grant them explicitly, scoped to `mailmanager-archive/<ArchiveId>`.
- Permissions-management actions (identity policies, `ReplicateEmailIdentityDkimSigningKey`, `ApplyTrackingConfigurationOverrides`) belong only in the security write tier.
- The plan withholds three send actions. The reference has seven: `SendEmail`, `SendBulkEmail`, `SendRawEmail`, `SendTemplatedEmail`, `SendBulkTemplatedEmail`, `SendCustomVerificationEmail`, `SendBounce`. Add an explicit Deny on all seven.
- Tag conditions (`aws:ResourceTag/*`) apply to identity, configuration-set, template, contact-list, dedicated-ip-pool, tenant and Mail Manager resources, not to import/export jobs or suppression entries.
- No IAM action exists for exporting the suppression list.

**Read role (plan section 7) and related reads**

| IAM action | Access level | Resource type(s) in the Authorization Reference | Action-level condition keys |
|---|---|---|---|
| `ses:GetAccount` | Read | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:ListEmailIdentities` | List | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:GetEmailIdentity` | Read | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetEmailIdentityPolicies` | Read | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:ListConfigurationSets` | List | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:GetConfigurationSet` | Read | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetConfigurationSetEventDestinations` | Read | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:ListSuppressedDestinations` | Read | `tenant` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetSuppressedDestination` | Read | `tenant` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetMessageInsights` | Read | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:GetEmailAddressInsights` | Read | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:BatchGetMetricData` | Read | `configuration-set`, `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetDomainStatisticsReport` | Read | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetBlacklistReports` | Read | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:ListEmailTemplates` | List | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:GetEmailTemplate` | Read | `template` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:TestRenderEmailTemplate` | Write | `template` | `ses:ApiVersion` |
| `ses:ListRecommendations` | Read | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:GetImportJob` | Read | `import-job` | `ses:ApiVersion` |
| `ses:ListImportJobs` | List | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:GetExportJob` | Read | `export-job` | `ses:ApiVersion`, `ses:ExportSourceType` |
| `ses:ListExportJobs` | List | (none; Resource `*`) | `ses:ApiVersion`, `ses:ExportSourceType` |
| `ses:GetDeliverabilityDashboardOptions` | Read | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:ListTagsForResource` | Read | `addon-instance`, `addon-subscription`, `configuration-set`, `contact-list`, `custom-verification-email-template`, `dedicated-ip-pool`, `deliverability-test-report`, `identity`, `mailmanager-archive`, `mailmanager-ingress-point`, `mailmanager-rule-set`, `mailmanager-smtp-relay`, `mailmanager-traffic-policy`, `template`, `tenant` | `ses:ApiVersion` |
| `ses:GetDedicatedIpPool` | Read | `dedicated-ip-pool` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:ListDedicatedIpPools` | List | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:ListTenants` | List | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:GetTenant` | Read | `tenant` | `aws:ResourceTag/*`, `ses:ApiVersion` |

**Write roles (ops tier)**

| IAM action | Access level | Resource type(s) in the Authorization Reference | Action-level condition keys |
|---|---|---|---|
| `ses:DeleteSuppressedDestination` | Write | `tenant` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutSuppressedDestination` | Write | `tenant` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:CreateImportJob` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:CreateExportJob` | Write | (none; Resource `*`) | `ses:ApiVersion`, `ses:ExportSourceType` |
| `ses:CancelExportJob` | Write | `export-job` | `ses:ApiVersion`, `ses:ExportSourceType` |
| `ses:CreateEmailTemplate` | Write | `template` | `aws:RequestTag/*`, `aws:TagKeys`, `ses:ApiVersion` |
| `ses:UpdateEmailTemplate` | Write | `template` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:DeleteEmailTemplate` | Write | `template` | `aws:ResourceTag/*`, `ses:ApiVersion` |

**Write roles (security tier)**

| IAM action | Access level | Resource type(s) in the Authorization Reference | Action-level condition keys |
|---|---|---|---|
| `ses:CreateEmailIdentity` | Write | `identity` | `aws:RequestTag/*`, `aws:TagKeys`, `ses:ApiVersion` |
| `ses:DeleteEmailIdentity` | Write | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutEmailIdentityDkimAttributes` | Write | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutEmailIdentityDkimSigningAttributes` | Write | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutEmailIdentityMailFromAttributes` | Write | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutEmailIdentityFeedbackAttributes` | Write | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutEmailIdentityConfigurationSetAttributes` | Write | `configuration-set`, `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:CreateEmailIdentityPolicy` | Permissions mgmt | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:UpdateEmailIdentityPolicy` | Permissions mgmt | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:DeleteEmailIdentityPolicy` | Permissions mgmt | `identity` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:ReplicateEmailIdentityDkimSigningKey` | Permissions mgmt | `identity` | `ses:ReplicaRegion` |
| `ses:CreateConfigurationSet` | Write | `configuration-set`, `dedicated-ip-pool`, `mailmanager-archive` | `aws:RequestTag/*`, `aws:TagKeys`, `ses:ApiVersion` |
| `ses:DeleteConfigurationSet` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:CreateConfigurationSetEventDestination` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:UpdateConfigurationSetEventDestination` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:DeleteConfigurationSetEventDestination` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetArchivingOptions` | Write | `configuration-set`, `mailmanager-archive` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetSuppressionOptions` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetSendingOptions` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetTrackingOptions` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetDeliveryOptions` | Write | `configuration-set`, `dedicated-ip-pool` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetReputationOptions` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:PutConfigurationSetVdmOptions` | Write | `configuration-set` | `aws:ResourceTag/*`, `ses:ApiVersion` |
| `ses:UpdateConfigurationSetSendingEnabled` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:PutAccountSuppressionAttributes` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:PutAccountSendingAttributes` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:PutAccountVdmAttributes` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:PutAccountDetails` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:UpdateAccountSendingEnabled` | Write | (none; Resource `*`) | `ses:ApiVersion` |
| `ses:TagResource` | Write | `addon-instance`, `addon-subscription`, `configuration-set`, `contact-list`, `custom-verification-email-template`, `dedicated-ip-pool`, `deliverability-test-report`, `identity`, `mailmanager-address-list`, `mailmanager-archive`, `mailmanager-ingress-point`, `mailmanager-rule-set`, `mailmanager-smtp-relay`, `mailmanager-traffic-policy`, `template`, `tenant` | `aws:RequestTag/*`, `aws:TagKeys`, `ses:ApiVersion` |
| `ses:UntagResource` | Write | `addon-instance`, `addon-subscription`, `configuration-set`, `contact-list`, `custom-verification-email-template`, `dedicated-ip-pool`, `deliverability-test-report`, `identity`, `mailmanager-address-list`, `mailmanager-archive`, `mailmanager-ingress-point`, `mailmanager-rule-set`, `mailmanager-smtp-relay`, `mailmanager-traffic-policy`, `template`, `tenant` | `aws:TagKeys`, `ses:ApiVersion` |

**Mail Manager (prefix is still `ses:`)**

| IAM action | Access level | Resource type(s) in the Authorization Reference | Action-level condition keys |
|---|---|---|---|
| `ses:ListArchives` | List | (none; Resource `*`) | - |
| `ses:GetArchive` | Read | `mailmanager-archive` | - |
| `ses:CreateArchive` | Write | `mailmanager-archive` | `aws:RequestTag/*`, `aws:TagKeys` |
| `ses:UpdateArchive` | Write | `mailmanager-archive` | - |
| `ses:DeleteArchive` | Write | `mailmanager-archive` | - |
| `ses:StartArchiveSearch` | Write | `mailmanager-archive` | - |
| `ses:GetArchiveSearch` | Read | `mailmanager-archive` | - |
| `ses:GetArchiveSearchResults` | Read | `mailmanager-archive` | - |
| `ses:StopArchiveSearch` | Write | `mailmanager-archive` | - |
| `ses:ListArchiveSearches` | List | (none; Resource `*`) | - |
| `ses:GetArchiveMessage` | Read | `mailmanager-archive` | - |
| `ses:GetArchiveMessageContent` | Read | `mailmanager-archive` | - |
| `ses:StartArchiveExport` | Write | `mailmanager-archive` | - |
| `ses:GetArchiveExport` | Read | `mailmanager-archive` | - |
| `ses:StopArchiveExport` | Write | `mailmanager-archive` | - |
| `ses:ListArchiveExports` | List | (none; Resource `*`) | - |
| `ses:ListIngressPoints` | List | (none; Resource `*`) | - |
| `ses:GetIngressPoint` | Read | `mailmanager-ingress-point` | - |
| `ses:CreateIngressPoint` | Write | `mailmanager-ingress-point` | `aws:RequestTag/*`, `aws:TagKeys`, `ses:MailManagerRuleSetArn`, `ses:MailManagerTrafficPolicyArn` |
| `ses:UpdateIngressPoint` | Write | `mailmanager-ingress-point` | `ses:MailManagerRuleSetArn`, `ses:MailManagerTrafficPolicyArn` |
| `ses:DeleteIngressPoint` | Write | `mailmanager-ingress-point` | - |
| `ses:ListRuleSets` | List | (none; Resource `*`) | - |
| `ses:GetRuleSet` | Read | `mailmanager-rule-set` | - |
| `ses:CreateRuleSet` | Write | `mailmanager-rule-set` | `aws:RequestTag/*`, `aws:TagKeys` |
| `ses:UpdateRuleSet` | Write | `mailmanager-rule-set` | - |
| `ses:DeleteRuleSet` | Write | `mailmanager-rule-set` | - |
| `ses:ListTrafficPolicies` | List | (none; Resource `*`) | - |
| `ses:GetTrafficPolicy` | Read | `mailmanager-traffic-policy` | - |
| `ses:CreateTrafficPolicy` | Write | `mailmanager-traffic-policy` | `aws:RequestTag/*`, `aws:TagKeys` |
| `ses:UpdateTrafficPolicy` | Write | `mailmanager-traffic-policy` | - |
| `ses:DeleteTrafficPolicy` | Write | `mailmanager-traffic-policy` | - |
| `ses:ListRelays` | List | (none; Resource `*`) | - |
| `ses:GetRelay` | Read | `mailmanager-smtp-relay` | - |
| `ses:CreateRelay` | Write | `mailmanager-smtp-relay` | `aws:RequestTag/*`, `aws:TagKeys` |
| `ses:ListAddressLists` | List | (none; Resource `*`) | - |
| `ses:GetAddressList` | Read | `mailmanager-address-list` | - |
| `ses:CreateAddressList` | Write | `mailmanager-address-list` | `aws:RequestTag/*`, `aws:TagKeys` |

**Send-type actions to withhold (explicit Deny recommended)**

| IAM action | Access level | Resource type(s) in the Authorization Reference | Action-level condition keys |
|---|---|---|---|
| `ses:SendEmail` | Write | `configuration-set`, `identity`, `template` | `ses:ApiVersion`, `ses:FeedbackAddress`, `ses:FromAddress`, `ses:FromDisplayName`, `ses:MultiRegionEndpointId`, `ses:Recipients`, `ses:TenantName` |
| `ses:SendBulkEmail` | Write | `configuration-set`, `identity`, `template` | `ses:ApiVersion`, `ses:MultiRegionEndpointId`, `ses:TenantName` |
| `ses:SendRawEmail` | Write | `configuration-set`, `identity` | `ses:ApiVersion`, `ses:FeedbackAddress`, `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients` |
| `ses:SendTemplatedEmail` | Write | `configuration-set`, `identity`, `template` | `ses:ApiVersion`, `ses:FeedbackAddress`, `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients` |
| `ses:SendBulkTemplatedEmail` | Write | `configuration-set`, `identity`, `template` | `ses:ApiVersion`, `ses:FeedbackAddress`, `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients` |
| `ses:SendCustomVerificationEmail` | Write | `custom-verification-email-template`, `identity` | `ses:ApiVersion`, `ses:FeedbackAddress`, `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients` |
| `ses:SendBounce` | Write | `identity` | `ses:ApiVersion`, `ses:FromAddress` |

**Resource types and ARN formats** (all `arn:${Partition}:ses:${Region}:${Account}:<suffix>`)

| Resource type | ARN suffix |
|---|---|
| `addon-instance` | `addon-instance/${AddonInstanceId}` |
| `addon-subscription` | `addon-subscription/${AddonSubscriptionId}` |
| `configuration-set` | `configuration-set/${ConfigurationSetName}` |
| `contact-list` | `contact-list/${ContactListName}` |
| `custom-verification-email-template` | `custom-verification-email-template/${TemplateName}` |
| `dedicated-ip-pool` | `dedicated-ip-pool/${DedicatedIPPool}` |
| `deliverability-test-report` | `deliverability-test-report/${ReportId}` |
| `export-job` | `export-job/${ExportJobId}` |
| `identity` | `identity/${IdentityName}` |
| `import-job` | `import-job/${ImportJobId}` |
| `mailmanager-address-list` | `mailmanager-address-list/${AddressListId}` |
| `mailmanager-archive` | `mailmanager-archive/${ArchiveId}` |
| `mailmanager-ingress-point` | `mailmanager-ingress-point/${IngressPointId}` |
| `mailmanager-rule-set` | `mailmanager-rule-set/${RuleSetId}` |
| `mailmanager-smtp-relay` | `mailmanager-smtp-relay/${RelayId}` |
| `mailmanager-traffic-policy` | `mailmanager-traffic-policy/${TrafficPolicyId}` |
| `multi-region-endpoint` | `multi-region-endpoint/${EndpointName}` |
| `reputation-policy` | `reputation-policy/${ReputationPolicyName}  (account segment is literally `aws`)` |
| `template` | `template/${TemplateName}` |
| `tenant` | `tenant/${TenantName}/${TenantId}` |


## 4. Mail Manager and classic receiving: regions; outbound archiving via config set

**Status: regions RESOLVED (ap-south-1 supported for both). Outbound archive via config set RESOLVED for API sends; SMTP, cross-account and email-processing-fee behaviour UNRESOLVED.**

**Mail Manager in ap-south-1: YES.**
- AWS What's New, 2025-01: "The new Regions include US East (Ohio), US West (San Francisco), Asia Pacific (Mumbai), Asia Pacific (Osaka) ..." (17 regions total). https://aws.amazon.com/about-aws/whats-new/2025/01/ses-mail-manager-available-new-regions/
- 2025-12: "Mail Manager is now offered in all commercial Regions where SES offers its core Outbound service" (27 total). https://aws.amazon.com/about-aws/whats-new/2025/12/ses-mail-manager-10-regions/ ; GovCloud added 2026-05.
- The General Reference lists a Mail Manager SMTP relay IP range for ap-south-1 (206.55.136.0/24). https://docs.aws.amazon.com/general/latest/gr/ses.html

**Classic SES email receiving in ap-south-1: YES.** The General Reference "Email Receiving endpoints" table lists "Asia Pacific (Mumbai) ap-south-1 inbound-smtp.ap-south-1.amazonaws.com" and says "Amazon SES does not support email receiving in the following Regions: AWS GovCloud (US-West) and AWS GovCloud (US-East)."

**Outbound archive via config set: YES, API v2 sends.**
- `PutConfigurationSetArchivingOptions`: "Associate the configuration set with a MailManager archive. When you send email using the SendEmail or SendBulkEmail operations the message as it will be given to the receiving SMTP server will be archived, along with the recipient information." Request body is `ArchiveArn` only. https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_PutConfigurationSetArchivingOptions.html
- What is archived: the message after DKIM signing ("retention of messages post-DKIM-signature"), per What's New 2025-02, billed "at the existing Mail Manager Archive price points". https://aws.amazon.com/about-aws/whats-new/2025/02/ses-outbound-delivers-mail-manager-archives/
- Developer guide: "all email sent using that configuration set will be archived to the email archive you designate." Default retention 180 days (overridable at archive creation); archive search is "limited to 30 days at a time". https://docs.aws.amazon.com/ses/latest/dg/eb-archiving.html . Quotas: 10 active archives, 1,000 search results, 1 parallel search, 1 parallel export, 250,000 exported results.
- Mail Manager ingress endpoints are SMTP-only and archive outbound mail through a rule-set action, a different path from the config-set option.

**UNRESOLVED**
1. Does SMTP-interface mail (SendRawEmail v2 under the hood) get archived through the config set? Docs name only SendEmail and SendBulkEmail. Test: send one mailbox-simulator message by SMTP with `X-SES-CONFIGURATION-SET` and one by API to a staging config set with an archive, then search the archive. This is a send, not read-only; do it in staging only.
2. Can the archive be in a different AWS account from the config set (plan puts the console in its own account)? The ArchiveArn pattern allows any account digits, but nothing states cross-account works. Assume same account and region until tested.
3. Is the $0.15/1,000 Mail Manager "Email Processing" fee also charged for archived outbound mail? Pricing page: "Email processing refers to emails processed by Mail Manager regardless of inbound receiving or outbound sending." Not stated for the config-set path.

## 9. Default configuration set per identity (PutEmailIdentityConfigurationSetAttributes)

**Status: RESOLVED for the general behaviour and precedence. SMTP-specific behaviour and From-address vs identity-ARN resolution are UNRESOLVED (docs are silent).**

Evidence (https://docs.aws.amazon.com/ses/latest/dg/managing-configuration-sets.html , "Understanding default configuration sets"):
- "A default configuration set automatically applies its rules to all messages that you send from the email identity associated with that configuration set."
- "Default configuration sets will only be applied if the identity is verified."
- "A default configuration set at the email address level overrides a default configuration set at the domain level."
- "A default configuration set at the domain level applies to all email addresses for that domain (unless you verify specific addresses for the domain)."
- "An email identity can be associated with only one configuration set at a time."
- "If you delete a configuration set that's designated as the default configuration set for an identity, and then attempt to send email through that identity, your call to Amazon SES fails with a 'bad request' error."
- "A default configuration set cannot be assigned to a verified identity that's being used by a delegate sender."
- Precedence: CreateEmailIdentity API ref: "The configuration set to use by default when sending from this identity. Note that any configuration set defined in the email sending request takes precedence." https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateEmailIdentity.html
- Cost: "If the configuration set you assign as a default has reputation metrics enabled, additional charges will be incurred for any mail sent using the default configuration set."
- Explicit header path: "If you are using the SMTP interface or the SendRawEmail API operation, you can specify a configuration set by including the following header ... X-SES-CONFIGURATION-SET". https://docs.aws.amazon.com/ses/latest/dg/using-configuration-sets-in-email.html
- Set at creation (`ConfigurationSetName` on CreateEmailIdentity) or later with `PutEmailIdentityConfigurationSetAttributes` (empty success output). https://docs.aws.amazon.com/ses/latest/dg/managing-configuration-sets-default-adding.html

**What the docs do not say:** no sentence says SMTP mail without the header uses the identity default (the docs speak of "all messages" and "every time email is sent from the identity"), and none says which identity is matched (header From, envelope MAIL FROM, or a SourceArn). Plan assumption "existing SMTP senders need no code change" is therefore plausible but not documented.

**Safe test (staging, one send):** set a default config set with an SNS or CloudWatch event destination on a test identity; send one mailbox-simulator message by SMTP with no header and one by API with no config set; confirm both produce events. Then send from an address identity whose default differs from its domain default, to see which wins.

**Plan-changing risk:** deleting or replacing a default config set (for example a Terraform destroy/replace) makes every send from that identity fail with a bad request. Use `lifecycle { prevent_destroy = true }` and change order (re-point identities first, then delete).

## 8. Event publishing: SNS (SSE-KMS), SQS, Firehose policies

**Status: RESOLVED, with one UNRESOLVED detail (exact `aws:SourceArn` to use in the SNS key policy).**

**SNS topic policy for SES (per config set).** https://docs.aws.amazon.com/ses/latest/dg/event-publishing-add-event-destination-sns.html
```json
{ "Effect": "Allow", "Principal": {"Service": "ses.amazonaws.com"}, "Action": "sns:Publish",
  "Resource": "arn:aws:sns:<region>:<acct>:<topic>",
  "Condition": {"StringEquals": {"AWS:SourceAccount": "<acct>",
    "AWS:SourceArn": "arn:aws:ses:<region>:<acct>:configuration-set/<name>"}} }
```
The doc also says "SES does not support FIFO type topics" (Standard only). One statement names one config set; for many sets use an `ArnLike` on `configuration-set/*` (inference).

**SSE-KMS topic with SES publishing: supported.** The SNS guide lists "Amazon Simple Email Service | ses.amazonaws.com" among event sources that work with encrypted topics, requires a customer managed key, and the key-policy statement is: Principal `{"Service": "ses.amazonaws.com"}`, Action `["kms:GenerateDataKey*", "kms:Decrypt"]`, Resource `"*"`. It recommends adding `aws:SourceAccount` and `aws:SourceArn` conditions "to further protect the KMS key from confused deputy attacks. Refer to service specific documentation ... for exact details". https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html . UNRESOLVED: the SES docs do not state the exact SourceArn SES sends for KMS calls. Start with `aws:SourceAccount` only plus `ArnLike aws:SourceArn = arn:aws:ses:<region>:<acct>:configuration-set/*`, and test in staging that events still flow; drop the ArnLike if they stop.

**SQS subscriber.** Queue policy (https://docs.aws.amazon.com/sns/latest/dg/subscribe-sqs-queue-to-sns-topic.html): Principal `{"Service": "sns.amazonaws.com"}`, Action `sqs:SendMessage`, Resource the queue ARN, Condition `ArnEquals aws:SourceArn` = topic ARN. If the queue is SSE-KMS (customer managed key), the key policy needs Principal `sns.amazonaws.com` with `kms:Decrypt` and `kms:GenerateDataKey*`. https://docs.aws.amazon.com/sns/latest/dg/sns-enable-encryption-for-topic-sqs-queue-subscriptions.html . Cross-account queue: "the subscription must be confirmed" when the subscriber is not the queue owner, so the plan's separate console account needs that step (or put SNS and SQS in the sender account and read the queue cross-account).

**SES to Firehose.** https://docs.aws.amazon.com/ses/latest/dg/event-publishing-add-event-destination-firehose.html
- Role permissions policy: `firehose:PutRecordBatch` on `arn:aws:firehose:<region>:<acct>:deliverystream/<name>`.
- Role trust policy: Principal `ses.amazonaws.com`, Action `sts:AssumeRole`, Condition `StringEquals` `AWS:SourceAccount` = account and `AWS:SourceArn` = `arn:aws:ses:<region>:<acct>:configuration-set/<name>`.
- The role is passed in the event-destination definition.

**Related KMS (import jobs).** For suppression import files encrypted with a CMK, SES needs a key-policy statement with Principal `ses.amazonaws.com`, Action `kms:Decrypt` ("SES can only attain permission from a customer managed key, not a default KMS key"). https://docs.aws.amazon.com/ses/latest/dg/sending-email-suppression-list.html

## 10. Terraform AWS provider and CloudFormation coverage

**Status: RESOLVED. Latest provider version confirmed: 6.69.1 (published 2026-10-15, registry API https://registry.terraform.io/v1/providers/hashicorp/aws). Resource lists checked against the docs tree at tag v6.69.1 (https://github.com/hashicorp/terraform-provider-aws).**

| Need | Native Terraform resource | Notes |
|---|---|---|
| Configuration set | `aws_sesv2_configuration_set` | delivery, reputation, sending, suppression, tracking, vdm options. **No archiving option** (no "archiv" anywhere in the doc). |
| Event destination | `aws_sesv2_configuration_set_event_destination` | blocks: `cloud_watch_destination`, `event_bridge_destination`, `kinesis_firehose_destination`, `pinpoint_destination`, `sns_destination` |
| Email identity | `aws_sesv2_email_identity` | has `configuration_set_name` (default config set) and `dkim_signing_attributes` (BYODKIM, `next_signing_key_length` for Easy DKIM); exposes `tokens`, `current_signing_key_length`, `last_key_generation_timestamp` |
| Feedback attrs | `aws_sesv2_email_identity_feedback_attributes` | yes |
| MAIL FROM | `aws_sesv2_email_identity_mail_from_attributes` | yes |
| Identity policy | `aws_sesv2_email_identity_policy` | yes |
| Account VDM | `aws_sesv2_account_vdm_attributes` | yes |
| Account suppression | `aws_sesv2_account_suppression_attributes` | yes |
| Others present | `aws_sesv2_dedicated_ip_pool`, `_dedicated_ip_assignment`, `_contact_list`, `_tenant`, `_tenant_resource_association`, `_multi_region_endpoint` | |
| Mail Manager archive | `aws_mailmanager_archive` | `retention_period` THREE_MONTHS .. PERMANENT, `kms_key_arn` |
| Mail Manager ingress point, rule set, traffic policy, relay | `aws_mailmanager_ingress_point`, `_rule_set`, `_traffic_policy`, `_relay` | native |
| Mail Manager address list | **none** | no `address_list` file in the docs tree |

**CloudFormation fallback exists.** The CloudFormation SES resource list includes `AWS::SES::MailManagerAddonInstance`, `MailManagerAddonSubscription`, `MailManagerAddressList`, `MailManagerArchive`, `MailManagerIngressPoint`, `MailManagerRelay`, `MailManagerRuleSet`, `MailManagerTrafficPolicy`, plus `AWS::SES::VdmAttributes`. https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_SES.html . Importantly `AWS::SES::ConfigurationSet` has an `ArchivingOptions` property (https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-configurationset.html), so `aws_cloudformation_stack` is the fallback for archive-enabled config sets and for address lists.

## 5. Suppression list export and pagination

**Status: no export API RESOLVED (none documented). Maximum `PageSize` UNRESOLVED (not documented for this operation).**

- No export operation exists for the account suppression list. The developer guide covers view (`ListSuppressedDestinations`), add/remove single (`PutSuppressedDestination`/`DeleteSuppressedDestination`) and bulk add/remove only through `CreateImportJob`. `CreateExportJob` supports only two sources, `METRICS_DATA` and `MESSAGE_INSIGHTS` ("It can only contain one of MetricsDataSource or MessageInsightsDataSource object"). The Service Reference has no suppression-export action. https://docs.aws.amazon.com/ses/latest/dg/sending-email-suppression-list.html , https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_ExportDataSource.html
- Pagination: `ListSuppressedDestinations` takes `PageSize`, `NextToken`, and filters `StartDate`, `EndDate`, `Reason` (BOUNCE | COMPLAINT). API ref for PageSize: "The number of results to show in a single call to ListSuppressedDestinations" and no maximum. The CLI reference likewise states none. A 2023 AWS blog: "If the account-level suppression list contains more than 1000 records, we need to use NextToken", with example code using `PageSize=1000`. https://aws.amazon.com/blogs/messaging-and-targeting/how-to-list-over-1000-email-addresses-from-account-level-suppression-list/ . For comparison, `ListEmailIdentities` documents "at least 0, and can be no more than 1000".
- Bulk limits confirmed: 100,000 addresses per file to add, 10,000 to delete, 20 concurrent import jobs, S3 bucket in the same Region; CMK-encrypted objects need a key-policy statement for `ses.amazonaws.com` (`kms:Decrypt`).
- Case sensitivity confirmed: "SES account suppression lists are case-sensitive ... API calls for suppression list management require an exact case match."
- Other facts: only hard bounces are added; account list entries are deleted after 90 days if account sending is paused; messages to listed addresses still count toward the daily quota.

**Mirror design:** paginate with `PageSize=1000`; incremental syncs via `StartDate` (documented as "added to the list after a certain date"). **Safe read-only test of the maximum:** call `ListSuppressedDestinations` with PageSize 1000, then 5000, and read whether it returns a ValidationException or silently caps.

## 6. Easy DKIM key rotation

**Status: automatic rotation RESOLVED (SES does it, no customer action, no API trigger). Rotation schedule UNRESOLVED (not documented). Customer-controlled rotation requires BYODKIM.**

- Automatic: "SES' Easy DKIM simplifies email authentication by managing and rotating DKIM keys on behalf of customers." https://aws.amazon.com/blogs/messaging-and-targeting/simplify-multi-region-email-sending-with-simple-email-services-deterministic-easy-dkim/ . Also "By hosting the signing keys, SES can automatically rotate signing credentials and mitigate the risk of any key leak." and "SES regularly rotates the keys". https://aws.amazon.com/blogs/messaging-and-targeting/dkim-troubleshooting-series-introduction-to-dkim-and-first-dns-hurdles/ , https://aws.amazon.com/blogs/messaging-and-targeting/dkim-troubleshooting-series-authentication-considerations/
- Mechanism (AWS blog "Your DKIM Status is Pending"): "At any point in time, SES has one key active for our domain. When SES sets up a key rotation, it first generates the new private-public key pair and publishes the public part into DNS ... Once the new key has been propagated in DNS, SES starts signing with it, while keeping the old public key present in DNS ... Finally, SES removes the old key ... the CNAME records in our DNS point to SES-managed records and they will be automatically updated". Two of the three CNAME targets resolving to an empty string `""` is "normal behavior": empty values mean revoked or not-yet-active keys. https://aws.amazon.com/blogs/messaging-and-targeting/dkim-troubleshooting-series-your-dkim-status-is-pending/
- Schedule: not in any official page. Community answers on re:Post (90 days, once a year) are unverified and not used.
- No rotate API for Easy DKIM. The only Easy DKIM control is key length: `PutEmailIdentityDkimSigningAttributes` with `SigningAttributesOrigin=AWS_SES` and `NextSigningKeyLength` (`RSA_1024_BIT`|`RSA_2048_BIT`); "You can't switch to a different key length more than once in a 24 hour period". `GetEmailIdentity` returns `CurrentSigningKeyLength`, `NextSigningKeyLength`, `LastKeyGenerationTimestamp`, `Status`. https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_PutEmailIdentityDkimSigningAttributes.html , .../API_DkimAttributes.html , https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-easy.html
- Manual rotation: BYODKIM ("with BYODKIM you can rotate the DKIM keys for your domains as often as you want"; RSA 1024-2048, selector TXT record, up to 72 h DNS propagation). Warning: while switching from Easy DKIM, "Amazon SES will not use Easy DKIM to sign your emails while BYODKIM is being set up and your DKIM status is in a pending state". https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-bring-your-own.html
- Multi-region: with Deterministic Easy DKIM, "Any subsequent DKIM key rotations or key length changes made to the parent identity are automatically propagated to all replica identities." https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-deed.html

**Consequence for the DNS health module:** verify the three CNAMEs exist and point to SES; do not alert on empty TXT values behind them. Show `LastKeyGenerationTimestamp` and DKIM `Status` from `GetEmailIdentity` as the rotation indicator. **Safe read-only test of schedule:** record `LastKeyGenerationTimestamp` for every identity daily and compute the observed interval.

## 7. Pricing: SNS, SQS, Firehose, GuardDuty Malware Protection for S3

**Status: RESOLVED for both ap-south-1 (Mumbai) and us-east-1. SNS free tier not confirmed.**

The pricing pages render their tables client-side, so figures come from the AWS data behind them: the pricing-page JSON (https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps/sns/USD/current/sns.json, published 2026-09-15; same path for guardduty) and the official AWS Price List files (https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSQueueService/current/ap-south-1/index.json and .../AmazonKinesisFirehose/current/ap-south-1/index.json). Pages: https://aws.amazon.com/sns/pricing/ , /sqs/pricing/ , /firehose/pricing/ , /guardduty/pricing/ . Prices are USD.

| Service | ap-south-1 (Mumbai) | us-east-1 |
|---|---|---|
| SNS Standard API requests | $0.50 per million (64 KB chunk = 1 request) | $0.50 per million |
| SNS delivery to SQS / Lambda | $0 ("Amazon SNS does not charge for per-message notification delivery when delivering messages to Amazon SQS and AWS Lambda") | $0 |
| SNS delivery to HTTP | $0.60 per million | $0.60 per million |
| SQS Standard requests | $0.40 per million (tier 1, to 100 B requests); first 1,000,000 requests per month free; 64 KB chunk = 1 request | $0.40 per million; same free tier |
| Firehose Direct PUT ingestion (first 500 TB) | $0.034 per GB, billed in 5 KB increments | $0.029 per GB, 5 KB increments |
| GuardDuty Malware Protection for S3, data scanned | $0.1125 per GB (first 1 GB/month free) | $0.09 per GB (first 1 GB free; page footnote: "price decreased from $0.60 to $0.09 per GB scanned") |
| GuardDuty Malware Protection for S3, objects | $0.271 per 1,000 objects (first 1,000/month free) | $0.215 per 1,000 objects (page example "4,000/1,000 * $0.215") |

Free-tier statement for GuardDuty: "monthly Free Tier allowance of 1000 requests and 1GB per month". The SNS page shows no SNS-specific request free tier in the text fetched; treat it as $0.

**Re-baseline of plan section 10 (my estimate, assumptions stated):** 1M mails/month at ~3 events each = 3M events. SNS 3M requests = $1.50. SQS: SNS-to-SQS delivery free; the worker's batched receive and delete are about 0.6M requests, inside the free million. Firehose: 3M records x 5 KB minimum = ~15 GB x $0.034 = ~$0.51. Total about $2 to $5 per month, so "low single-digit dollars" holds. Firehose's 5 KB rounding means small events cost about 3 to 5x their real size.

**Other pricing facts found (affects plan sections 1 and 10).** SES moved to plans from 2026-07-21: Essentials (no fixed fee), Pro ($105 per account per region per month), Enterprise ($500). "New SES accounts and account x region combinations with no metered SES activity since June 1, 2025 will start on the Essentials plan beginning July 21, 2026", so the new console account will start on Essentials. Mail Manager: "Email Processing" $0.15 per 1,000 emails; Open ingress endpoint $50 per month ("Charges apply even when endpoint status is 'Closed'"; add-on on Essentials and Pro, 1 included on Enterprise); archiving "$2 per GB of emails ingested; $0.19 per GB per month for storage and search", an add-on on every plan. VDM "SES deliverability" $0.07 per 1,000 emails (0-10M), shown as included (check mark) in the plan table. https://aws.amazon.com/ses/pricing/ . The plan's archive, endpoint and VDM figures match; the Mail Manager email-processing fee is new and not in the plan.

## Decisions this changes in the plan

1. **Region: stay on ap-south-1.** Mail Manager (since 2025-01) and classic receiving are both supported in Mumbai, so the section 12 risk "may force a different inbound region" is closed and no fallback to classic receipt rules is needed for region reasons.
2. **Terraform has two gaps.** `aws_sesv2_configuration_set` has no archiving option and there is no `aws_mailmanager_address_list`. Manage archive-enabled config sets (and any address list) with `aws_cloudformation_stack` (`AWS::SES::ConfigurationSet` has `ArchivingOptions`; `AWS::SES::MailManagerAddressList` exists). Everything else in the plan is native in provider 6.69.1. Pin the provider and re-check before Phase 1.
3. **Rate-limit design.** Use a single 1 rps token bucket per (account, region) for all control-plane reads until the Phase 0 burst test says otherwise; BatchGetMetricData up to 16 rps. Reputation and metrics should come from CloudWatch and BatchGetMetricData, not per-click control-plane calls.
4. **GetMessageInsights is an enrichment only.** 1 call/sec, a 30-day window at best, VDM required (presumed), and possibly blind to simulator and multi-recipient mail. Staging test matrix assertions must come from our own SNS to SQS ingestion, not GetMessageInsights. For backfill or reconciliation use `CreateExportJob` with `MessageInsightsDataSource` (10,000 message cap, 1 call/sec).
5. **IAM changes.** The read role must also include `ses:StartArchiveSearch`, `ses:GetArchiveSearch`, `ses:GetArchiveSearchResults`, `ses:GetArchiveMessage`, `ses:GetArchiveMessageContent` on the archive ARN (search start is classed Write). Add an explicit Deny on all seven send actions, not three. `ListSuppressedDestinations`/`GetSuppressedDestination` can only be granted on `*` at account level.
6. **Suppression mirror is polling only.** No export exists; mirror by paging `ListSuppressedDestinations` (PageSize 1000 until tested) with `StartDate` for increments. Keep stored case.
7. **DNS drift rules must tolerate Easy DKIM rotation.** Empty TXT values behind the DKIM CNAMEs are normal; alert on missing or wrong CNAMEs and on DKIM `Status`, and display `LastKeyGenerationTimestamp`. No rotate API exists; rotation on our schedule would mean BYODKIM, which is a security-tier change with a signing gap.
8. **Default config set is a single point of failure.** Deleting or replacing a config set that is some identity's default makes all sends from that identity fail with a bad request. Make config sets `prevent_destroy`, and sequence changes (re-point identities, then delete). The "no code change in senders" claim for SMTP senders is plausible but undocumented: run the one-send staging test before Phase 7.
9. **Outbound body archive.** Works for API v2 SendEmail/SendBulkEmail via config set. Verify SMTP mail is archived before promising bodies for mail sent over SMTP. Archive-versus-config-set account and region alignment is untested, so assume the archive lives in the sending account and region, not the separate console account, and read it cross-account via an assumed role. Archive retention in Terraform starts at THREE_MONTHS (console default is 180 days); the plan's 30-day outbound body retention must be enforced by our own redaction/expiry or by a lifecycle on exported copies, not by archive retention.
10. **Event plumbing across accounts.** The SES event destination, SNS topic policy, KMS key and Firehose role are in the sending account (their conditions use that account's id). The console's SQS queue in another account needs a confirmed cross-account subscription plus a queue policy with `aws:SourceArn` = topic. Decide whether SNS and SQS live in the sender account (read cross-account) or the console account.
11. **Cost section 10 re-baseline.** Event pipeline is about $2-5/month (confirmed). New items: SES plan model from 2026-07-21 (new account starts on Essentials), Mail Manager email processing $0.15 per 1,000 emails, open ingress endpoint $50/month on Essentials and Pro. GuardDuty S3 scanning in Mumbai is $0.1125/GB plus $0.271 per 1,000 objects.

## Open tests (all safe and small)

| Test | Type | Closes |
|---|---|---|
| GetMessageInsights on 25-day, 35-day, simulator, multi-recipient message; repeat with VDM off | read-only | item 1 |
| Burst GetAccount/ListEmailIdentities/ListSuppressedDestinations at 3 rps; check per-action vs shared | read-only | item 2 |
| ListSuppressedDestinations PageSize 1000 vs 5000 | read-only | item 5 |
| Daily record of `LastKeyGenerationTimestamp` per identity | read-only | item 6 |
| SMTP no-header send and API send on staging identity with default config set, both with event destination | one staging send | item 9 |
| SMTP and API sends to a staging config set with archive; cross-account archive attempt | staging sends | item 4 |
| Add `aws:SourceArn` to the SNS key policy and confirm events still flow | staging | item 8 |
