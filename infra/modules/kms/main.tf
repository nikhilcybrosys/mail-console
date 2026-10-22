# Three customer-managed keys, all with automatic rotation:
#   events - SNS topics, SQS queues, Firehose stream, raw-events bucket, alerts topic
#   data   - content/attachments bucket, RDS, Secrets Manager, ECR, Mail Manager archives
#   audit  - audit bucket, CloudTrail bucket, CloudWatch log groups
#
# Every key policy starts with the standard "account root" statement so that IAM
# policies (see modules/iam_roles) control which principals may use a key. Only
# AWS SERVICE principals that cannot be given an IAM policy are named below, each
# pinned with aws:SourceAccount (and aws:SourceArn where AWS documents it).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
}

# ---------------------------------------------------------------- events key
data "aws_iam_policy_document" "events" {
  statement {
    sid       = "EnableIamPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # SES -> encrypted SNS topic. AWS docs (SNS "encrypted topics" + SES event
  # destinations) require the service principal to have GenerateDataKey* and
  # Decrypt, and recommend SourceAccount/SourceArn against confused deputy.
  # For SES the SourceArn is the CONFIGURATION SET that publishes.
  statement {
    sid       = "SesPublishToEncryptedTopic"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:ses:${local.region}:${local.account_id}:configuration-set/*"]
    }
  }

  # SNS service itself: needed so the topic can encrypt messages and so SNS can
  # write into the SSE-KMS SQS queue. SourceAccount only: AWS documents this
  # condition for service principals but SNS does not always send SourceArn on
  # its KMS calls. TODO-VERIFY in staging; tighten with SourceArn if it works.
  statement {
    sid       = "SnsEncryptDecrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # CloudWatch alarms and EventBridge rules publish to the (events-key) alerts
  # topic; AWS requires these two service principals in the key policy.
  statement {
    sid       = "AlarmsAndEventBridgePublishToAlertsTopic"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "events" {
  description             = "${var.name_prefix} events: SNS/SQS/Firehose/raw-events/alerts"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy                  = data.aws_iam_policy_document.events.json
}

resource "aws_kms_alias" "events" {
  name          = "alias/${var.name_prefix}-events"
  target_key_id = aws_kms_key.events.key_id
}

# ------------------------------------------------------------------ data key
data "aws_iam_policy_document" "data" {
  statement {
    sid       = "EnableIamPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # SES / Mail Manager archives and SES import jobs read & write encrypted
  # objects. TODO-VERIFY exact principal/conditions for Mail Manager archive
  # CMKs in Phase 0 (docs name ses.amazonaws.com; kept to this account).
  statement {
    sid       = "SesArchivesAndImports"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant"]
    resources = ["*"]
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

resource "aws_kms_key" "data" {
  description             = "${var.name_prefix} data: S3 content, RDS, Secrets Manager, ECR, archives"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy                  = data.aws_iam_policy_document.data.json
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

# ----------------------------------------------------------------- audit key
data "aws_iam_policy_document" "audit" {
  statement {
    sid       = "EnableIamPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # CloudWatch Logs encrypts log groups with this key (AWS-documented policy).
  statement {
    sid       = "CloudWatchLogs"
    effect    = "Allow"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }

  # CloudTrail encrypts its log files with this key (AWS-documented policy).
  statement {
    sid       = "CloudTrailEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # AWS Config delivers snapshots into the trail bucket (optional feature).
  statement {
    sid       = "ConfigDelivery"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "audit" {
  description             = "${var.name_prefix} audit: audit bucket, CloudTrail, log groups"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy                  = data.aws_iam_policy_document.audit.json
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name_prefix}-audit"
  target_key_id = aws_kms_key.audit.key_id
}
