# Alarms -> `alerts` SNS topic (SSE-KMS), CloudTrail (multi-region, validated, KMS),
# EventBridge detection of SES control-plane changes, GuardDuty, Access Analyzer and
# (optional) AWS Config.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  trail_name = "${var.name_prefix}-trail"
  alarm_to   = [aws_sns_topic.alerts.arn]
}

# ----------------------------------------------------------------- alerts topic
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.events_key_arn
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "AlarmsAndEventBridgePublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
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
  statement {
    sid       = "AccountOwner"
    actions   = ["sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:Subscribe", "sns:ListSubscriptionsByTopic", "sns:Publish", "sns:DeleteTopic"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [local.account_id]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish", "sns:Subscribe"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_email_addresses)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sns_topic_subscription" "https" {
  for_each  = nonsensitive(toset(var.alert_https_endpoints))
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "https"
  endpoint  = each.value
}

# ---------------------------------------------------------------- queue alarms
resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  for_each            = var.queues
  alarm_name          = "${var.name_prefix}-${each.key}-dlq-not-empty"
  alarm_description   = "Poison messages in the ${each.key} DLQ. Inspect, fix, then redrive."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value.dlq_name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  for_each            = var.queues
  alarm_name          = "${var.name_prefix}-${each.key}-oldest-message-age"
  alarm_description   = "Oldest ${each.key} message waiting > 300 s: worker down or too slow."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = each.value.queue_name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 300
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

resource "aws_cloudwatch_metric_alarm" "worker_tasks_zero" {
  alarm_name          = "${var.name_prefix}-worker-no-running-tasks"
  alarm_description   = "No worker task is running: events are not being ingested."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  dimensions          = { ClusterName = var.cluster_name, ServiceName = var.worker_service_name }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

# No events at all: SES publishes nothing for N hours. Missing data = breaching.
resource "aws_cloudwatch_metric_alarm" "no_events" {
  count               = var.enable_no_events_alarm ? 1 : 0
  alarm_name          = "${var.name_prefix}-no-ses-events"
  alarm_description   = "SES published no events for ${var.no_events_hours} hours (pipeline broken or senders not using a config set)."
  namespace           = "AWS/SNS"
  metric_name         = "NumberOfMessagesPublished"
  dimensions          = { TopicName = var.ses_events_topic_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = var.no_events_hours
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

# ------------------------------------------------------------------------ ALB
resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.name_prefix}-alb-5xx"
  alarm_description   = "ALB or targets returning 5xx."
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alb_5xx_threshold
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to

  metric_query {
    id          = "total"
    expression  = "elb + target"
    label       = "5xx total"
    return_data = true
  }
  metric_query {
    id = "elb"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_ELB_5XX_Count"
      dimensions  = { LoadBalancer = var.alb_arn_suffix }
      period      = 300
      stat        = "Sum"
    }
  }
  metric_query {
    id = "target"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_Target_5XX_Count"
      dimensions  = { LoadBalancer = var.alb_arn_suffix }
      period      = 300
      stat        = "Sum"
    }
  }
}

# ------------------------------------------------------------------------ RDS
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.name_prefix}-rds-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = var.rds_identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.name_prefix}-rds-free-storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = var.rds_identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.rds_free_storage_bytes_threshold
  comparison_operator = "LessThanThreshold"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${var.name_prefix}-rds-connections"
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = { DBInstanceIdentifier = var.rds_identifier }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = var.rds_max_connections_threshold
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

# ------------------------------------------------------- SES reputation (AWS/SES)
# Account-level metrics Reputation.BounceRate / Reputation.ComplaintRate are
# fractions (0.02 = 2%). They are emitted hourly-ish, so missing data is not breaching.
resource "aws_cloudwatch_metric_alarm" "ses_rate" {
  for_each = {
    bounce-warn    = { metric = "Reputation.BounceRate", threshold = var.bounce_warn }
    bounce-page    = { metric = "Reputation.BounceRate", threshold = var.bounce_page }
    complaint-warn = { metric = "Reputation.ComplaintRate", threshold = var.complaint_warn }
    complaint-page = { metric = "Reputation.ComplaintRate", threshold = var.complaint_page }
  }
  alarm_name          = "${var.name_prefix}-ses-${each.key}"
  alarm_description   = "SES ${each.value.metric} above ${each.value.threshold} (review threshold 5%/0.1%, pause 10%/0.5%)."
  namespace           = "AWS/SES"
  metric_name         = each.value.metric
  statistic           = "Average"
  period              = 3600
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

# ------------------------------------------------------------------------ WAF
resource "aws_cloudwatch_metric_alarm" "waf_blocked" {
  alarm_name          = "${var.name_prefix}-waf-blocked-spike"
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  dimensions          = { WebACL = var.web_acl_name, Region = local.region, Rule = "ALL" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.waf_blocked_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_to
  ok_actions          = local.alarm_to
}

# ---------------------------------------------------------------- CloudTrail
data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-trail"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-trail/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"]
    }
  }
  dynamic "statement" {
    for_each = var.enable_config ? [1] : []
    content {
      sid       = "ConfigAclAndList"
      actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
      resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-trail"]
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
  dynamic "statement" {
    for_each = var.enable_config ? [1] : []
    content {
      sid       = "ConfigWrite"
      actions   = ["s3:PutObject"]
      resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-trail/config/AWSLogs/${local.account_id}/Config/*"]
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
}

module "trail_bucket" {
  source            = "../_secure_bucket"
  name              = "${var.name_prefix}-${local.account_id}-trail"
  kms_key_arn       = var.audit_key_arn
  enforce_key_id    = false
  extra_policy_json = [data.aws_iam_policy_document.trail_bucket.json]
  lifecycle_rules = [{
    id              = "expire-logs"
    expiration_days = var.trail_log_retention_days
    noncurrent_days = 30
  }]
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = module.trail_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.audit_key_arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    dynamic "data_resource" {
      for_each = length(var.s3_data_event_bucket_arns) > 0 ? [1] : []
      content {
        type   = "AWS::S3::Object"
        values = [for b in var.s3_data_event_bucket_arns : "${b}/"]
      }
    }
  }

  depends_on = [module.trail_bucket]
}

# ---------------------------------------------- SES control-plane change detection
locals {
  critical_ses_apis = [
    "PutEmailIdentityDkimAttributes", "PutEmailIdentityDkimSigningAttributes",
    "DeleteEmailIdentity", "PutEmailIdentityMailFromAttributes",
    "PutAccountSendingAttributes", "PutAccountSuppressionAttributes",
    "CreateConfigurationSetEventDestination", "UpdateConfigurationSetEventDestination",
    "DeleteConfigurationSetEventDestination", "DeleteConfigurationSet",
  ]
  non_console_exclusions = concat(var.console_role_arns, var.trusted_admin_principal_arns)

  alert_transformer_paths = {
    event = "$.detail.eventName"
    who   = "$.detail.userIdentity.arn"
    ip    = "$.detail.sourceIPAddress"
    when  = "$.time"
  }
}

# (1) Any SES write API called by a principal that is not a console role / trusted admin.
resource "aws_cloudwatch_event_rule" "ses_write_non_console" {
  name        = "${var.name_prefix}-ses-write-non-console"
  description = "SES write API from a principal that is not a console role or trusted admin"
  event_pattern = jsonencode({
    source        = ["aws.ses"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ses.amazonaws.com"]
      eventName = [
        { prefix = "Put" }, { prefix = "Create" }, { prefix = "Delete" },
        { prefix = "Update" }, { prefix = "Verify" }, { prefix = "Set" },
      ]
      "$or" = [
        { userIdentity = { type = [{ "anything-but" = ["AssumedRole"] }] } },
        { userIdentity = { sessionContext = { sessionIssuer = { arn = [{ "anything-but" = local.non_console_exclusions }] } } } },
      ]
    }
  })
}

# (2) The dangerous APIs, whoever calls them (including the console write roles).
resource "aws_cloudwatch_event_rule" "ses_critical" {
  name        = "${var.name_prefix}-ses-critical-change"
  description = "DKIM / identity delete / account sending / event-destination changes"
  event_pattern = jsonencode({
    source        = ["aws.ses"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ses.amazonaws.com"]
      eventName   = local.critical_ses_apis
    }
  })
}

resource "aws_cloudwatch_event_target" "alerts" {
  for_each = {
    non-console = aws_cloudwatch_event_rule.ses_write_non_console.name
    critical    = aws_cloudwatch_event_rule.ses_critical.name
  }
  rule = each.value
  arn  = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths    = local.alert_transformer_paths
    input_template = "\"SES change <event> by <who> from <ip> at <when> (rule ${each.key})\""
  }
}

resource "aws_cloudwatch_metric_alarm" "ses_change" {
  for_each = {
    non-console = aws_cloudwatch_event_rule.ses_write_non_console.name
    critical    = aws_cloudwatch_event_rule.ses_critical.name
  }
  alarm_name          = "${var.name_prefix}-ses-change-${each.key}"
  alarm_description   = "EventBridge rule ${each.value} matched an SES control-plane change."
  namespace           = "AWS/Events"
  metric_name         = "TriggeredRules"
  dimensions          = { RuleName = each.value }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_to
}

# --------------------------------------------------- GuardDuty + Access Analyzer
resource "aws_guardduty_detector" "this" {
  enable = true
}

resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.this.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "rds" {
  detector_id = aws_guardduty_detector.this.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${var.name_prefix}-external-access"
  type          = "ACCOUNT"
}

# ------------------------------------------------------------- AWS Config (optional)
data "aws_iam_policy_document" "config_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = var.enable_config ? 1 : 0
  name               = "${var.name_prefix}-aws-config"
  assume_role_policy = data.aws_iam_policy_document.config_trust.json
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  count    = var.enable_config ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = var.enable_config ? 1 : 0
  name           = "${var.name_prefix}-channel"
  s3_bucket_name = module.trail_bucket.id
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_config_rule" "managed" {
  for_each = var.enable_config ? toset([
    "S3_BUCKET_PUBLIC_READ_PROHIBITED", "S3_BUCKET_SSL_REQUESTS_ONLY",
    "RDS_STORAGE_ENCRYPTED", "RDS_INSTANCE_PUBLIC_ACCESS_CHECK",
    "IAM_USER_NO_POLICIES_CHECK", "CLOUD_TRAIL_ENABLED",
  ]) : toset([])
  name = "${var.name_prefix}-${lower(replace(each.key, "_", "-"))}"
  source {
    owner             = "AWS"
    source_identifier = each.key
  }
  depends_on = [aws_config_configuration_recorder_status.this]
}
