# SES -> (SNS -> SQS -> worker) and (Firehose -> S3 raw archive).
#
# Config sets and event destinations are managed here. Identities are NOT managed
# unless manage_identities = true (so existing senders are never clobbered).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition

  plain_sets   = { for k, v in var.configuration_sets : k => v if !v.archive }
  archive_sets = { for k, v in var.configuration_sets : k => v if v.archive && var.outbound_archive_arn != null }

  # Names of every set that exists (archive sets only once their stack is created).
  set_names = merge(
    { for k, v in aws_sesv2_configuration_set.plain : k => v.configuration_set_name },
    { for k, v in aws_cloudformation_stack.archive : k => v.outputs["ConfigSetName"] },
  )

  set_arns   = [for k in keys(var.configuration_sets) : "arn:${local.partition}:ses:${local.region}:${local.account_id}:configuration-set/${k}"]
  topic_arn  = "arn:${local.partition}:sns:${local.region}:${local.account_id}:${var.name_prefix}-ses-events"
  all_events = ["SEND", "REJECT", "BOUNCE", "COMPLAINT", "DELIVERY", "DELIVERY_DELAY", "RENDERING_FAILURE", "SUBSCRIPTION", "OPEN", "CLICK"]
}

# ----------------------------------------------------------------- SNS -> SQS
data "aws_iam_policy_document" "ses_publish" {
  # AWS docs pattern: ses.amazonaws.com may publish, only for OUR configuration sets.
  statement {
    sid       = "SesPublishFromOurConfigSets"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [local.topic_arn]
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "AWS:SourceArn"
      values   = local.set_arns
    }
  }
}

module "events" {
  source                = "../_sns_to_sqs"
  name_prefix           = var.name_prefix
  name                  = "ses-events"
  kms_key_arn           = var.events_key_arn
  publisher_policy_json = data.aws_iam_policy_document.ses_publish.json
}

# ------------------------------------------------------------ configuration sets
resource "aws_sesv2_configuration_set" "plain" {
  for_each               = local.plain_sets
  configuration_set_name = each.key

  delivery_options {
    tls_policy = var.tls_policy
  }
  reputation_options {
    reputation_metrics_enabled = true
  }
  sending_options {
    sending_enabled = true
  }
  suppression_options {
    suppressed_reasons = var.suppressed_reasons
  }

  # Phase 0 finding: deleting a config set that is an identity's default makes EVERY
  # send from that identity fail ("bad request"). To remove a set: re-point the
  # identities first, then drop prevent_destroy in a reviewed change.
  lifecycle {
    prevent_destroy = true
  }
}

# The provider's aws_sesv2_configuration_set has NO archiving_options argument
# (PutConfigurationSetArchivingOptions is not exposed). CloudFormation
# AWS::SES::ConfigurationSet does support ArchivingOptions.ArchiveArn, so the
# archive-enabled sets are created through a CloudFormation stack. Event
# destinations below still attach to them by name with native resources.
resource "aws_cloudformation_stack" "archive" {
  for_each = local.archive_sets
  name     = "${var.name_prefix}-cfg-${each.key}"

  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Resources = {
      ConfigSet = {
        Type = "AWS::SES::ConfigurationSet"
        Properties = {
          Name               = each.key
          ArchivingOptions   = { ArchiveArn = var.outbound_archive_arn }
          DeliveryOptions    = { TlsPolicy = var.tls_policy }
          ReputationOptions  = { ReputationMetricsEnabled = true }
          SendingOptions     = { SendingEnabled = true }
          SuppressionOptions = { SuppressedReasons = var.suppressed_reasons }
        }
      }
    }
    Outputs = {
      ConfigSetName = { Value = { Ref = "ConfigSet" } }
    }
  })

  # Same reason as above: never delete a config set that may be an identity default.
  lifecycle {
    prevent_destroy = true
  }
}

# Account-level VDM (optional, costs money).
resource "aws_sesv2_account_vdm_attributes" "this" {
  count       = var.enable_vdm ? 1 : 0
  vdm_enabled = "ENABLED"
  dashboard_attributes {
    engagement_metrics = "ENABLED"
  }
  guardian_attributes {
    optimized_shared_delivery = "ENABLED"
  }
}

# ---------------------------------------------------------------- SNS destination
resource "aws_sesv2_configuration_set_event_destination" "sns" {
  for_each               = local.set_names
  configuration_set_name = each.value
  event_destination_name = "sns-events"

  event_destination {
    enabled              = true
    matching_event_types = local.all_events
    sns_destination {
      topic_arn = module.events.topic_arn
    }
  }
}

# ------------------------------------------------- Firehose -> raw-events bucket
module "raw_events" {
  source      = "../_secure_bucket"
  name        = "${var.name_prefix}-${local.account_id}-raw-events"
  kms_key_arn = var.events_key_arn
  object_lock = var.raw_events_object_lock
  lifecycle_rules = [{
    id              = "expire-after-retention"
    expiration_days = var.raw_events_expiration_days
    noncurrent_days = 1
  }]
}

data "aws_iam_policy_document" "firehose_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "firehose_delivery" {
  statement {
    sid = "WriteRawEvents"
    actions = [
      "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
      "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
    ]
    resources = [module.raw_events.arn, "${module.raw_events.arn}/*"]
  }
  statement {
    sid       = "UseEventsKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:CreateGrant", "kms:DescribeKey"]
    resources = [var.events_key_arn]
  }
}

resource "aws_iam_role" "firehose" {
  name               = "${var.name_prefix}-firehose-raw-events"
  assume_role_policy = data.aws_iam_policy_document.firehose_trust.json
}

resource "aws_iam_role_policy" "firehose" {
  name   = "deliver-to-raw-events"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose_delivery.json
}

resource "aws_kinesis_firehose_delivery_stream" "raw" {
  name        = "${var.name_prefix}-ses-raw-events"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = var.events_key_arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = module.raw_events.arn
    kms_key_arn         = var.events_key_arn
    prefix              = "events/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    buffering_size      = 5
    buffering_interval  = 300
    compression_format  = "GZIP"
  }

  depends_on = [aws_iam_role_policy.firehose]
}

# Role SES assumes to put records into Firehose.
data "aws_iam_policy_document" "ses_to_firehose_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    # AWS docs: also pin the configuration set(s) that deliver to this stream.
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.set_arns
    }
  }
}

data "aws_iam_policy_document" "ses_to_firehose" {
  statement {
    sid       = "PutToOurStream"
    actions   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
    resources = [aws_kinesis_firehose_delivery_stream.raw.arn]
  }
  # Stream is SSE-KMS. TODO-VERIFY whether the producer needs these on DirectPut.
  statement {
    sid       = "UseEventsKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.events_key_arn]
  }
}

resource "aws_iam_role" "ses_to_firehose" {
  name               = "${var.name_prefix}-ses-to-firehose"
  assume_role_policy = data.aws_iam_policy_document.ses_to_firehose_trust.json
}

resource "aws_iam_role_policy" "ses_to_firehose" {
  name   = "put-records"
  role   = aws_iam_role.ses_to_firehose.id
  policy = data.aws_iam_policy_document.ses_to_firehose.json
}

resource "aws_sesv2_configuration_set_event_destination" "firehose" {
  for_each               = local.set_names
  configuration_set_name = each.value
  event_destination_name = "firehose-raw"

  event_destination {
    enabled              = true
    matching_event_types = local.all_events
    kinesis_firehose_destination {
      delivery_stream_arn = aws_kinesis_firehose_delivery_stream.raw.arn
      iam_role_arn        = aws_iam_role.ses_to_firehose.arn
    }
  }

  depends_on = [aws_iam_role_policy.ses_to_firehose]
}

# ------------------------------------------------- optional identity management
# Import-friendly: ignore_changes on DKIM so an existing identity (e.g. BYODKIM or a
# rotated Easy-DKIM key) is never rewritten; prevent_destroy so a mistaken removal
# from the map cannot delete a live sending domain.
resource "aws_sesv2_email_identity" "this" {
  for_each               = var.manage_identities ? var.identities : {}
  email_identity         = each.key
  configuration_set_name = each.value.default_configuration_set

  dkim_signing_attributes {
    next_signing_key_length = each.value.dkim_key_length
  }

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [dkim_signing_attributes]
  }

  depends_on = [aws_sesv2_configuration_set.plain, aws_cloudformation_stack.archive]
}

resource "aws_sesv2_email_identity_mail_from_attributes" "this" {
  for_each = { for k, v in(var.manage_identities ? var.identities : {}) : k => v if v.mail_from_domain != null }

  email_identity         = aws_sesv2_email_identity.this[each.key].email_identity
  mail_from_domain       = each.value.mail_from_domain
  behavior_on_mx_failure = "USE_DEFAULT_VALUE"
}
