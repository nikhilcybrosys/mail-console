# IAM for the console. Role map:
#
#   console-web            ECS task role of the web service. READ-ONLY on SES.
#                          Can sts:AssumeRole ONLY into the two write roles, and only
#                          with sts:SourceIdentity = acting user's e-mail.
#   console-worker         ECS task role of ingest_ses_events + sync_ses_state.
#   console-write-ops      assumed per approved action: suppression + templates.
#   console-write-security assumed per approved action: identities/DKIM/event dests.
#   ecs-execution          pulls the image, writes logs, injects secrets. No SES.
#
# EVERY role above carries the permissions boundary `console-boundary`, which has an
# explicit Deny on every ses:Send* action. An explicit Deny wins over any Allow, so even
# a future policy mistake cannot give a console role the ability to send mail.
#
# SES action names come from the AWS Service Authorization Reference (service
# "ses", IAM prefix ses:, v2 API operation names). TODO-VERIFY items are marked.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  ses_arn    = "arn:${local.partition}:ses:*:${local.account_id}"

  # Never allowed for any console role (matches ses:Send* incl. SendBounce).
  ses_send_actions = [
    "ses:SendEmail",
    "ses:SendBulkEmail",
    "ses:SendRawEmail",
    "ses:SendCustomVerificationEmail",
    "ses:SendTemplatedEmail",
    "ses:SendBulkTemplatedEmail",
    "ses:SendBounce",
    "ses:Send*", # forward-compatible catch-all for future Send* APIs
  ]

  web_role_name      = "${var.name_prefix}-console-web"
  worker_role_name   = "${var.name_prefix}-console-worker"
  ops_role_name      = "${var.name_prefix}-console-write-ops"
  security_role_name = "${var.name_prefix}-console-write-security"
  exec_role_name     = "${var.name_prefix}-ecs-execution"

  write_role_arns = [
    "arn:${local.partition}:iam::${local.account_id}:role/${local.ops_role_name}",
    "arn:${local.partition}:iam::${local.account_id}:role/${local.security_role_name}",
  ]
  console_role_names = [local.web_role_name, local.worker_role_name, local.ops_role_name, local.security_role_name, local.exec_role_name]

  source_identity_pattern = "*@${var.allowed_email_domain}"

  # SES read actions shared by the web role (full list) - plan section 7.
  ses_read_actions = [
    "ses:GetAccount",
    "ses:ListEmailIdentities",
    "ses:GetEmailIdentity",
    "ses:GetEmailIdentityPolicies",
    "ses:ListConfigurationSets",
    "ses:GetConfigurationSet",
    "ses:GetConfigurationSetEventDestinations",
    "ses:ListSuppressedDestinations",
    "ses:GetSuppressedDestination",
    "ses:GetMessageInsights",
    "ses:GetEmailAddressInsights",
    "ses:BatchGetMetricData",
    "ses:GetDomainStatisticsReport",
    "ses:GetBlacklistReports",
    "ses:ListEmailTemplates",
    "ses:GetEmailTemplate",
    "ses:TestRenderEmailTemplate", # preview only, does not send
    "ses:ListRecommendations",
    "ses:GetImportJob",
    "ses:ListImportJobs",
    "ses:GetDeliverabilityDashboardOptions",
    "ses:GetIngressPoint", # Mail Manager health (read-only)
    "ses:ListIngressPoints",
    "ses:GetRuleSet",
    "ses:ListRuleSets",
    "ses:GetTrafficPolicy",
    "ses:ListTrafficPolicies",
  ]

  # Subset for the worker / sync task: state snapshots only.
  ses_worker_read_actions = [
    "ses:GetAccount",
    "ses:ListEmailIdentities",
    "ses:GetEmailIdentity",
    "ses:GetEmailIdentityPolicies",
    "ses:ListConfigurationSets",
    "ses:GetConfigurationSet",
    "ses:GetConfigurationSetEventDestinations",
    "ses:ListSuppressedDestinations",
    "ses:GetSuppressedDestination",
    "ses:BatchGetMetricData",
  ]
}

# ============================================================= boundary policy
data "aws_iam_policy_document" "boundary" {
  # The boundary is a CEILING, not a grant: effective permissions = identity policy
  # INTERSECT this document. It therefore lists every service family the console
  # legitimately touches, and then removes the dangerous parts with explicit Denies.
  statement {
    sid    = "CeilingAllowedServices"
    effect = "Allow"
    actions = [
      "ses:*", "sqs:*", "s3:*", "kms:*", "cloudwatch:*", "sts:AssumeRole", "sts:SetSourceIdentity",
      "secretsmanager:GetSecretValue", "ecr:*", "logs:CreateLogStream", "logs:PutLogEvents",
    ]
    resources = ["*"]
  }

  # THE rule: no console role can ever send e-mail, whatever else is attached.
  statement {
    sid       = "DenyAllSesSending"
    effect    = "Deny"
    actions   = local.ses_send_actions
    resources = ["*"]
  }

  # SES only in the allowed regions.
  statement {
    sid       = "DenySesOutsideAllowedRegions"
    effect    = "Deny"
    actions   = ["ses:*"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }

  # A console role must not be able to lift its own ceiling or mint new principals.
  statement {
    sid    = "DenyIamSelfEscalation"
    effect = "Deny"
    actions = [
      "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
      "iam:CreateRole", "iam:CreateUser", "iam:CreateAccessKey", "iam:AttachRolePolicy",
      "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicyVersion",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${var.name_prefix}-console-boundary"
  description = "Permissions boundary for every console role: hard Deny on ses:Send*"
  policy      = data.aws_iam_policy_document.boundary.json
}

# ================================================================ trust policies
data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:ecs:${local.region}:${local.account_id}:*"]
    }
  }
}

# Write roles: trust ONLY the web task role, and only when sts:SourceIdentity is set
# to an e-mail in the allowed domain. A request without SourceIdentity fails the
# StringLike condition (missing key = no match), so anonymous assumption is impossible.
data "aws_iam_policy_document" "write_trust" {
  statement {
    sid     = "WebRoleWithSourceIdentityOnly"
    actions = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.web.arn]
    }
    condition {
      test     = "StringLike"
      variable = "sts:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }
}

# =============================================================== console-web role
resource "aws_iam_role" "web" {
  name                 = local.web_role_name
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

data "aws_iam_policy_document" "web" {
  # SES read. Most of these actions have no resource-level scoping (list/get-account
  # style), so Resource is "*", fenced by the region condition.
  statement {
    sid       = "SesReadOnly"
    effect    = "Allow"
    actions   = local.ses_read_actions
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }

  # Mail Manager archive search/read, ONLY on the named archives (resource type
  # mailmanager-archive). No export, no delete.
  dynamic "statement" {
    for_each = length(var.archive_arns) > 0 ? [1] : []
    content {
      sid    = "MailManagerArchiveReadOnly"
      effect = "Allow"
      actions = [
        "ses:GetArchive", "ses:StartArchiveSearch", "ses:GetArchiveSearch",
        "ses:GetArchiveSearchResults", "ses:StopArchiveSearch",
        "ses:GetArchiveMessage", "ses:GetArchiveMessageContent",
      ]
      resources = var.archive_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.archive_arns) > 0 ? [1] : []
    content {
      sid       = "MailManagerArchiveList" # List* APIs take no resource
      effect    = "Allow"
      actions   = ["ses:ListArchives", "ses:ListArchiveSearches"]
      resources = ["*"]
    }
  }

  # CloudWatch metrics for the dashboard (AWS/SES, AWS/SQS...). Read-only, no resource scoping.
  statement {
    sid       = "CloudWatchMetricsRead"
    effect    = "Allow"
    actions   = ["cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"]
    resources = ["*"]
  }

  # Pipeline-health panel: queue depth only (the worker does the consuming).
  statement {
    sid       = "SqsQueueAttributesOnly"
    effect    = "Allow"
    actions   = ["sqs:GetQueueAttributes", "sqs:GetQueueUrl"]
    resources = var.queue_arns
  }

  # Attachment download (after the app checks the GuardDuty scan tag).
  statement {
    sid       = "ContentBucketRead"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging"]
    resources = ["${var.content_bucket_arn}/*"]
  }

  # Decrypt objects in the content bucket / secrets encrypted by the data key.
  statement {
    sid       = "DecryptDataKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.data_key_arn]
  }

  # Privilege step-up: may assume ONLY the two write roles, and must name the user.
  statement {
    sid       = "AssumeWriteRolesWithSourceIdentity"
    effect    = "Allow"
    actions   = ["sts:AssumeRole", "sts:SetSourceIdentity"]
    resources = local.write_role_arns
    condition {
      test     = "StringLike"
      variable = "sts:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }

  # Belt and braces: explicit deny even though the boundary already has it.
  statement {
    sid       = "DenySesSend"
    effect    = "Deny"
    actions   = local.ses_send_actions
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "web" {
  name   = "console-web"
  role   = aws_iam_role.web.id
  policy = data.aws_iam_policy_document.web.json
}

# ============================================================ console-worker role
resource "aws_iam_role" "worker" {
  name                 = local.worker_role_name
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

data "aws_iam_policy_document" "worker" {
  # Consume from the event queues only (no SendMessage, no PurgeQueue).
  statement {
    sid       = "SqsConsume"
    effect    = "Allow"
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"]
    resources = var.queue_arns
  }

  # SNS/SQS envelope is encrypted with the events key.
  statement {
    sid       = "DecryptEventsKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.events_key_arn]
  }

  # State snapshots (sync_ses_state): read-only subset of SES.
  statement {
    sid       = "SesReadSubset"
    effect    = "Allow"
    actions   = local.ses_worker_read_actions
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }

  statement {
    sid       = "CloudWatchMetricsRead"
    effect    = "Allow"
    actions   = ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"]
    resources = ["*"]
  }

  # Append audit rows. PutObject only: no Get, no Delete, no PutObjectRetention.
  statement {
    sid       = "AuditBucketAppend"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.audit_bucket_arn}/*"]
  }

  statement {
    sid       = "EncryptAuditObjects"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:DescribeKey"]
    resources = [var.audit_key_arn]
  }

  statement {
    sid       = "DenySesSend"
    effect    = "Deny"
    actions   = local.ses_send_actions
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "worker" {
  name   = "console-worker"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker.json
}

# ======================================================== console-write-ops role
resource "aws_iam_role" "write_ops" {
  name                 = local.ops_role_name
  assume_role_policy   = data.aws_iam_policy_document.write_trust.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = 3600 # IAM minimum; the app requests DurationSeconds=900
}

data "aws_iam_policy_document" "write_ops" {
  # Suppression list edits and import jobs. Suppression APIs have no required
  # resource type, hence "*". Every allow requires aws:SourceIdentity (CloudTrail
  # attribution) and the allowed-region condition.
  statement {
    sid    = "SuppressionWrites"
    effect = "Allow"
    actions = [
      "ses:PutSuppressedDestination", "ses:DeleteSuppressedDestination",
      "ses:CreateImportJob", "ses:GetImportJob",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }

  # Template CRUD (v1.5). Scoped to template resources.
  statement {
    sid       = "TemplateCrud"
    effect    = "Allow"
    actions   = ["ses:CreateEmailTemplate", "ses:UpdateEmailTemplate", "ses:DeleteEmailTemplate", "ses:GetEmailTemplate"]
    resources = ["${local.ses_arn}:template/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }

  # Bulk suppression files: app uploads the CSV under imports/ then calls CreateImportJob.
  # TODO-VERIFY (Phase 0): whether SES reads the S3 object with the caller's credentials.
  statement {
    sid       = "ImportFileUpload"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.content_bucket_arn}/imports/*"]
  }

  statement {
    sid       = "ImportFileEncryption"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.data_key_arn]
  }

  statement {
    sid       = "DenySesSend"
    effect    = "Deny"
    actions   = local.ses_send_actions
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "write_ops" {
  name   = "console-write-ops"
  role   = aws_iam_role.write_ops.id
  policy = data.aws_iam_policy_document.write_ops.json
}

# =================================================== console-write-security role
resource "aws_iam_role" "write_security" {
  name                 = local.security_role_name
  assume_role_policy   = data.aws_iam_policy_document.write_trust.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = 3600
}

data "aws_iam_policy_document" "write_security" {
  # Identity, DKIM, MAIL FROM, feedback and identity-policy changes.
  statement {
    sid    = "IdentityWrites"
    effect = "Allow"
    actions = [
      "ses:CreateEmailIdentity", "ses:DeleteEmailIdentity",
      "ses:PutEmailIdentityDkimAttributes", "ses:PutEmailIdentityDkimSigningAttributes",
      "ses:PutEmailIdentityMailFromAttributes", "ses:PutEmailIdentityFeedbackAttributes",
      "ses:PutEmailIdentityConfigurationSetAttributes",
      "ses:CreateEmailIdentityPolicy", "ses:UpdateEmailIdentityPolicy", "ses:DeleteEmailIdentityPolicy",
      "ses:GetEmailIdentity", "ses:GetEmailIdentityPolicies",
    ]
    resources = ["${local.ses_arn}:identity/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }

  # Configuration sets and their event destinations. PutEmailIdentityConfigurationSetAttributes
  # also names the config set as a resource, so it is covered here as well.
  statement {
    sid    = "ConfigurationSetWrites"
    effect = "Allow"
    actions = [
      "ses:CreateConfigurationSet", "ses:DeleteConfigurationSet", "ses:GetConfigurationSet",
      "ses:CreateConfigurationSetEventDestination", "ses:UpdateConfigurationSetEventDestination",
      "ses:DeleteConfigurationSetEventDestination", "ses:GetConfigurationSetEventDestinations",
      "ses:PutConfigurationSetDeliveryOptions", "ses:PutConfigurationSetReputationOptions",
      "ses:PutConfigurationSetSendingOptions", "ses:PutConfigurationSetSuppressionOptions",
      "ses:PutConfigurationSetTrackingOptions", "ses:PutConfigurationSetVdmOptions",
      "ses:PutConfigurationSetArchivingOptions",
      "ses:PutEmailIdentityConfigurationSetAttributes",
    ]
    resources = ["${local.ses_arn}:configuration-set/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }

  # Account-level attributes (no resource type).
  statement {
    sid    = "AccountAttributeWrites"
    effect = "Allow"
    actions = [
      "ses:PutAccountSendingAttributes", "ses:PutAccountSuppressionAttributes",
      "ses:PutAccountVdmAttributes", "ses:GetAccount",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceIdentity"
      values   = [local.source_identity_pattern]
    }
  }

  # TODO-VERIFY: if Create/UpdateConfigurationSetEventDestination returns AccessDenied
  # on the SNS/Firehose target, add iam:PassRole for the single SES->Firehose role with
  # iam:PassedToService = ses.amazonaws.com. Deliberately NOT granted until proven needed.

  statement {
    sid       = "DenySesSend"
    effect    = "Deny"
    actions   = local.ses_send_actions
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "write_security" {
  name   = "console-write-security"
  role   = aws_iam_role.write_security.id
  policy = data.aws_iam_policy_document.write_security.json
}

# ================================================================ ecs-execution
resource "aws_iam_role" "execution" {
  name                 = local.exec_role_name
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_trust.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "EcrAuthToken" # no resource-level scoping exists for this action
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "EcrPullOurRepoOnly"
    effect    = "Allow"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [var.ecr_repository_arn]
  }

  statement {
    sid       = "WriteTaskLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/${var.name_prefix}/*:log-stream:*"]
  }

  statement {
    sid       = "InjectSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = var.secret_arns
  }

  statement {
    sid       = "DecryptSecretsWithDataKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.data_key_arn]
  }

  statement {
    sid       = "DenySesSend"
    effect    = "Deny"
    actions   = local.ses_send_actions
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "ecs-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}
