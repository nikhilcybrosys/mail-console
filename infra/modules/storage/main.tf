# audit bucket        : append-only copy of the app's audit log (Object Lock)
# content bucket      : attachments, inbound raw mail, opted-in outbound bodies,
#                       suppression-import files. NO Object Lock on purpose
#                       (erasure requests must be honoured, plan section 7).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

module "audit" {
  source      = "../_secure_bucket"
  name        = "${var.name_prefix}-${local.account_id}-audit"
  kms_key_arn = var.audit_key_arn
  object_lock = var.audit_object_lock
  lifecycle_rules = [{
    id              = "expire-after-retention"
    expiration_days = var.audit_expiration_days
    noncurrent_days = 1
  }]
}

# SES import jobs read suppression CSVs from imports/. TODO-VERIFY (Phase 0
# spike): whether SES reads with the caller's credentials (then this statement
# is unnecessary) or as the service principal. Scoped to one prefix + account.
data "aws_iam_policy_document" "content_extra" {
  dynamic "statement" {
    for_each = var.allow_ses_import_jobs ? [1] : []
    content {
      sid       = "SesImportJobsReadImportsPrefix"
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-content/imports/*"]
      principals {
        type        = "Service"
        identifiers = ["ses.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [local.account_id]
      }
    }
  }
}

module "content" {
  source            = "../_secure_bucket"
  name              = "${var.name_prefix}-${local.account_id}-content"
  kms_key_arn       = var.data_key_arn
  extra_policy_json = var.allow_ses_import_jobs ? [data.aws_iam_policy_document.content_extra.json] : []
  lifecycle_rules = [
    { id = "outbound-bodies", prefix = "outbound/", expiration_days = var.outbound_body_retention_days, noncurrent_days = 7 },
    { id = "inbound-mail", prefix = "inbound/", expiration_days = var.inbound_retention_days, noncurrent_days = 7 },
    { id = "attachments", prefix = "attachments/", expiration_days = var.inbound_retention_days, noncurrent_days = 7 },
    { id = "suppression-imports", prefix = "imports/", expiration_days = 7, noncurrent_days = 1 },
  ]
}

# ---- GuardDuty Malware Protection for S3 (content bucket) --------------------
# The role is exactly the policy from the GuardDuty docs. The plan tags each
# scanned object GuardDutyMalwareScanStatus=<result>; the app must refuse to
# serve an attachment until the tag says NO_THREATS_FOUND.
data "aws_iam_policy_document" "gd_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["malware-protection-plan.guardduty.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "gd_permissions" {
  statement {
    sid       = "ManageGuardDutyEventRule"
    actions   = ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets"]
    resources = ["arn:${local.partition}:events:${data.aws_region.current.region}:${local.account_id}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"]
    condition {
      test     = "StringLike"
      variable = "events:ManagedBy"
      values   = ["malware-protection-plan.guardduty.amazonaws.com"]
    }
  }
  statement {
    sid       = "ReadGuardDutyEventRule"
    actions   = ["events:DescribeRule", "events:ListTargetsByRule"]
    resources = ["arn:${local.partition}:events:${data.aws_region.current.region}:${local.account_id}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"]
  }
  statement {
    sid       = "EnableS3EventBridgeNotifications"
    actions   = ["s3:PutBucketNotification", "s3:GetBucketNotification"]
    resources = [module.content.arn]
  }
  statement {
    sid       = "CheckBucketOwnership"
    actions   = ["s3:ListBucket"]
    resources = [module.content.arn]
  }
  statement {
    sid       = "ValidationObject"
    actions   = ["s3:PutObject"]
    resources = ["${module.content.arn}/malware-protection-resource-validation-object"]
  }
  statement {
    sid       = "ScanAndTag"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObjectTagging", "s3:PutObjectVersionTagging"]
    resources = ["${module.content.arn}/*"]
  }
  statement {
    sid       = "UseDataKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = [var.data_key_arn]
  }
}

resource "aws_iam_role" "guardduty_scan" {
  count              = var.enable_malware_protection ? 1 : 0
  name               = "${var.name_prefix}-guardduty-malware-scan"
  assume_role_policy = data.aws_iam_policy_document.gd_trust.json
}

resource "aws_iam_role_policy" "guardduty_scan" {
  count  = var.enable_malware_protection ? 1 : 0
  name   = "scan-content-bucket"
  role   = aws_iam_role.guardduty_scan[0].id
  policy = data.aws_iam_policy_document.gd_permissions.json
}

resource "aws_guardduty_malware_protection_plan" "content" {
  count = var.enable_malware_protection ? 1 : 0
  role  = aws_iam_role.guardduty_scan[0].arn

  protected_resource {
    s3_bucket {
      bucket_name     = module.content.id
      object_prefixes = ["inbound/", "attachments/"]
    }
  }

  actions {
    tagging {
      status = "ENABLED"
    }
  }

  tags = { Purpose = "attachment-malware-scan" }

  depends_on = [aws_iam_role_policy.guardduty_scan]
}
