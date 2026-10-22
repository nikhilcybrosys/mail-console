# Rough monthly cost (USD)

Estimates from remembered ap-south-1 list prices, ~1M mails/month, a handful of users. **Not a quote:** re-check with the
AWS Pricing Calculator before apply. Phase 0 confirmed: event pipeline USD 2-5; Mail Manager processing USD 0.15 per 1,000 inbound emails;
open ingress endpoint USD 50/month; GuardDuty S3 scanning in Mumbai USD 0.1125/GB + USD 0.271 per 1,000 objects.

| Component | Staging (1 web, t4g.small, single-AZ) | Production (2 web, t4g.medium Multi-AZ) | Notes |
|---|---|---|---|
| VPC interface endpoints (9 services x 2 AZ) | 170 | 170 | ~USD 9.6 per endpoint-AZ. **Biggest surprise.** 3 AZ = 260. Trim `interface_endpoint_services` in staging (6 services = 115, none + NAT only = 0) |
| NAT gateway (1) + data | 45 | 45 | Needed for OIDC provider (decision D1). ~USD 41 fixed + traffic |
| Fargate | 30 | 50 | web 0.5 vCPU/1 GB, worker 0.25/0.5, sync ~USD 1 |
| ALB | 22 | 25 | + LCU |
| WAFv2 | 12 | 14 | ACL USD 5 + ~7 rules + requests + log ingestion |
| RDS PostgreSQL 16 | 32 | 120 | gp3 50 GB, backups within DB size, Performance Insights 7 d free |
| KMS (3 CMKs + requests) | 5 | 8 | USD 1/key + API calls (SQS/SNS/S3 with bucket keys) |
| Secrets Manager (5 secrets) | 2 | 3 | USD 0.40 each |
| CloudWatch (logs, Container Insights, ~25 alarms, flow logs) | 12 | 25 | log retention 30 d staging / 90 d prod |
| S3 (6 buckets) + Object Lock | 3 | 8 | grows with raw events and audit |
| SNS + SQS + Firehose | 3 | 5 | Firehose bills in 5 KB increments |
| CloudTrail (1 trail + S3 data events) | 2 | 4 | first management trail free |
| GuardDuty (foundation + S3 + RDS login + malware plan) | 5 | 15 | scales with CloudTrail events and scanned GB |
| AWS Config (optional, off in staging) | 0 | 5 | |
| ECR + Access Analyzer | 1 | 1 | |
| Mail Manager: ingress endpoint | 0 (off) | 50 | `enable_inbound`; decision D5 |
| Mail Manager: archive + processing | 1 | 10 | USD 2/GB ingested + 0.19/GB-month; 3-month minimum retention |
| **Subtotal** | **~340** | **~560** | |
| Optional: SES VDM (`enable_vdm`) | 0 | +70 | USD 0.07 per 1,000 mails |

## Against the plan's estimate (USD 150-250)

The plan underestimated: **interface endpoints alone are ~USD 170**. Levers, biggest first:

1. Endpoints: keep only what must stay private (sqs, secretsmanager, kms, ecr.api, ecr.dkr, logs, sts); route `email`, `monitoring` over NAT. Saves ~50.
2. Staging with NAT and no interface endpoints: staging falls to ~USD 170.
3. Skip Mail Manager inbound until Phase 5: saves ~60.
4. Single-AZ endpoints (`interface_endpoint_az_count = 1`): halves the endpoint line, at the cost of AZ fault tolerance for private API access.
5. Production realistic range: ~USD 400 (trimmed endpoints, inbound later) to ~USD 560 (as built).

Excluded: SES sending charges (unchanged), Route 53, ACM (free), cross-region DR copies, data transfer beyond the NAT line, support plan.
