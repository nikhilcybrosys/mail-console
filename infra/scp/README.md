# Suggested Service Control Policies (NOT applied)

These are documents for a human to review and attach through AWS Organizations to the
OU that holds the mail-console account. Nothing in Terraform applies them.

| File | Purpose |
|---|---|
| 01-deny-ses-send.json | The console account never sends mail: deny all seven ses:Send* actions for everyone. Do NOT attach this to the account that hosts your real senders. |
| 02-restrict-ses-writes.json | SES control-plane writes only from the two console write roles, the Terraform role and Mail Manager rule-action role. |
| 03-region-restriction.json | Deny everything outside ap-south-1 (+ us-east-1 for global services). Widen when adding regions. |
| 04-protect-security-services.json | Cannot stop CloudTrail/GuardDuty/Config, delete key material, change Object Lock, or use the root user. |
| 05-no-static-keys-and-protect-boundary.json | No IAM users or access keys; the console boundary policy and roles are tamper-proof. |

Before attaching: replace the placeholder role names (`terraform-admin`, `break-glass-admin`)
with the real ones, test in a sandbox OU, and keep each file under the 5,120-character SCP limit.
Role-name patterns assume the default prefixes `mc-staging` / `mc-prod`.
