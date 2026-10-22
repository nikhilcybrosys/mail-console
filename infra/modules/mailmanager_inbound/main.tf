# Mail Manager: MX inbound.<domain> -> ingress point -> traffic policy (accept only
# our inbound domain) -> rule set: ARCHIVE + SNS notification (headers only) +
# optional raw copy to S3. Native provider resources are used (aws_mailmanager_*).
#
# DNS is NOT managed here. After apply, a human creates:
#     inbound.<domain>.  MX  10  <a_record from output ingress_point_a_record>
# (the output explains the exact value; Mail Manager gives an A-record hostname.)
#
# Attachments: write_to_s3 stores the WHOLE raw message (not extracted attachments).
# GuardDuty Malware Protection (modules/storage) scans objects under inbound/.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  inbound    = var.enable_inbound
}

# --------------------------------------------------------------------- archives
resource "aws_mailmanager_archive" "inbound" {
  count       = local.inbound ? 1 : 0
  name        = "${var.name_prefix}-inbound"
  kms_key_arn = var.data_key_arn
  retention {
    retention_period = var.inbound_retention
  }
}

resource "aws_mailmanager_archive" "outbound" {
  count       = var.enable_outbound_archive ? 1 : 0
  name        = "${var.name_prefix}-outbound"
  kms_key_arn = var.data_key_arn
  retention {
    retention_period = var.outbound_retention
  }
}

# ---------------------------------------------------- notification topic + queue
# The Mail Manager role below is authorised by its identity policy, so the topic
# needs no extra publisher statements.
module "events" {
  count       = local.inbound ? 1 : 0
  source      = "../_sns_to_sqs"
  name_prefix = var.name_prefix
  name        = "inbound-events"
  kms_key_arn = var.events_key_arn
}

# ------------------------------------------------- role Mail Manager assumes
data "aws_iam_policy_document" "mm_trust" {
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
  }
}

data "aws_iam_policy_document" "mm_actions" {
  count = local.inbound ? 1 : 0

  statement {
    sid       = "PublishInboundNotifications"
    actions   = ["sns:Publish"]
    resources = [module.events[0].topic_arn]
  }
  statement {
    sid       = "WriteRawMail"
    actions   = ["s3:PutObject"]
    resources = ["${var.content_bucket_arn}/inbound/*"]
  }
  statement {
    sid       = "UseKeys"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.data_key_arn, var.events_key_arn]
  }
}

resource "aws_iam_role" "rule_actions" {
  count              = local.inbound ? 1 : 0
  name               = "${var.name_prefix}-mailmanager-rule-actions"
  assume_role_policy = data.aws_iam_policy_document.mm_trust.json
}

resource "aws_iam_role_policy" "rule_actions" {
  count  = local.inbound ? 1 : 0
  name   = "rule-actions"
  role   = aws_iam_role.rule_actions[0].id
  policy = data.aws_iam_policy_document.mm_actions[0].json
}

# -------------------------------------------------------------- traffic policy
resource "aws_mailmanager_traffic_policy" "inbound" {
  count                  = local.inbound ? 1 : 0
  name                   = "${var.name_prefix}-inbound"
  default_action         = "DENY"
  max_message_size_bytes = var.max_message_size_bytes

  policy_statement {
    action = "ALLOW"
    condition {
      string_expression {
        operator = "ENDS_WITH"
        values   = ["@${var.inbound_domain}"]
        evaluate {
          attribute = "RECIPIENT"
        }
      }
    }
  }
}

# -------------------------------------------------------------------- rule set
resource "aws_mailmanager_rule_set" "inbound" {
  count = local.inbound ? 1 : 0
  name  = "${var.name_prefix}-inbound"

  rule {
    name = "archive-and-notify"

    action {
      archive {
        target_archive        = aws_mailmanager_archive.inbound[0].id
        action_failure_policy = "CONTINUE"
      }
    }

    # Metadata only (HEADERS): SNS messages are limited to 256 KB and the body is in the archive.
    action {
      publish_to_sns {
        topic_arn             = module.events[0].topic_arn
        role_arn              = aws_iam_role.rule_actions[0].arn
        payload_type          = "HEADERS"
        encoding              = "UTF-8"
        action_failure_policy = "CONTINUE"
      }
    }

    dynamic "action" {
      for_each = var.store_raw_mail_in_s3 ? [1] : []
      content {
        write_to_s3 {
          s3_bucket             = var.content_bucket_id
          s3_prefix             = "inbound/"
          s3_sse_kms_key_id     = var.data_key_arn
          role_arn              = aws_iam_role.rule_actions[0].arn
          action_failure_policy = "CONTINUE"
        }
      }
    }
  }
}

# --------------------------------------------------------------- ingress point
resource "aws_mailmanager_ingress_point" "inbound" {
  count             = local.inbound ? 1 : 0
  name              = "${var.name_prefix}-inbound"
  type              = var.ingress_auth_mode
  rule_set_id       = aws_mailmanager_rule_set.inbound[0].id
  traffic_policy_id = aws_mailmanager_traffic_policy.inbound[0].id
  tls_policy        = var.tls_policy

  dynamic "ingress_point_configuration" {
    for_each = var.ingress_auth_mode == "MTLS" ? [1] : []
    content {
      tls_auth_configuration {
        trust_store {
          ca_content = var.mtls_ca_pem
        }
      }
    }
  }

  network_configuration {
    public_network_configuration {
      ip_type = "IPV4"
    }
  }
}
