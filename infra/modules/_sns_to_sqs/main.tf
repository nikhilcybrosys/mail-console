# Internal building block: SNS Standard topic (SSE-KMS) -> SQS queue (SSE-KMS)
# with a DLQ. Used for SES events and for Mail Manager inbound notifications.
#
# Decision (raw_message_delivery = false): we KEEP the SNS envelope so the
# worker can check TopicArn / MessageId / SignatureVersion and de-duplicate on
# MessageId. The cost is ~0.5 KB per message and one extra json.loads().

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  topic_name = "${var.name_prefix}-${var.name}"
}

resource "aws_sns_topic" "this" {
  name              = local.topic_name
  kms_master_key_id = var.kms_key_arn
}

data "aws_iam_policy_document" "topic" {
  # Keep the account owner able to manage the topic.
  statement {
    sid    = "AccountOwner"
    effect = "Allow"
    actions = [
      "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:AddPermission",
      "sns:RemovePermission", "sns:DeleteTopic", "sns:Subscribe",
      "sns:ListSubscriptionsByTopic", "sns:Publish",
    ]
    resources = [aws_sns_topic.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Publishers other than the account itself (e.g. ses.amazonaws.com) are
  # injected by the caller, always with SourceAccount + SourceArn conditions.
  source_policy_documents = var.publisher_policy_json != null ? [var.publisher_policy_json] : []

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish", "sns:Subscribe"]
    resources = [aws_sns_topic.this.arn]
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

resource "aws_sns_topic_policy" "this" {
  arn    = aws_sns_topic.this.arn
  policy = data.aws_iam_policy_document.topic.json
}

# ---- queues -----------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.topic_name}-dlq"
  message_retention_seconds = 1209600 # 14 days (maximum)
  kms_master_key_id         = var.kms_key_arn
}

resource "aws_sqs_queue" "main" {
  name                       = "${local.topic_name}-queue"
  visibility_timeout_seconds = var.visibility_timeout_seconds
  receive_wait_time_seconds  = 20 # long polling
  message_retention_seconds  = 345600
  kms_master_key_id          = var.kms_key_arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 5
  })
}

# Only the main queue may use this DLQ.
resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.main.arn]
  })
}

data "aws_iam_policy_document" "queue" {
  # The ONLY allow: SNS delivering from THIS topic. Everything else (workers,
  # redrive tools) is authorised by identity policies on the task roles.
  statement {
    sid       = "AllowOnlyThisTopic"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.main.arn]
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.this.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.main.arn]
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

resource "aws_sqs_queue_policy" "main" {
  queue_url = aws_sqs_queue.main.id
  policy    = data.aws_iam_policy_document.queue.json
}

resource "aws_sns_topic_subscription" "main" {
  topic_arn            = aws_sns_topic.this.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.main.arn
  raw_message_delivery = false
  depends_on           = [aws_sqs_queue_policy.main]
}
