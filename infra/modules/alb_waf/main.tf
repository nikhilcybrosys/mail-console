# Public entry point: ALB (HTTPS only, TLS 1.2+) behind WAFv2.
#
# Host routing:
#   <domain_name>          -> web target group (the console)
#   <mailview_domain_name> -> mailview target group (SAME ECS service, same container
#                             port) but only for mailview_path_patterns.
#   any other Host / path  -> fixed 404 (blocks direct-IP and wrong-host probing).
#
# COOKIE RULE (app contract, cannot be enforced by an ALB): the mailview host must
# NEVER set or receive cookies. Being a separate registrable domain means the
# console's session cookie is never sent there; the app must also never emit
# Set-Cookie on mailview requests (tests in the app repo assert this).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_elb_service_account" "this" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# ----------------------------------------------------------- access-log bucket
# ALB access logs cannot be delivered to an SSE-KMS bucket, so this one uses SSE-S3.
data "aws_iam_policy_document" "alb_logs" {
  statement {
    sid       = "AlbDeliveryOldRegions"
    actions   = ["s3:PutObject"]
    resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-alb-logs/alb/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }
  }
  statement {
    sid       = "AlbDeliveryNewRegions"
    actions   = ["s3:PutObject"]
    resources = ["arn:${local.partition}:s3:::${var.name_prefix}-${local.account_id}-alb-logs/alb/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }
}

module "logs" {
  source            = "../_secure_bucket"
  name              = "${var.name_prefix}-${local.account_id}-alb-logs"
  kms_key_arn       = null
  extra_policy_json = [data.aws_iam_policy_document.alb_logs.json]
  lifecycle_rules = [{
    id              = "expire-access-logs"
    expiration_days = var.access_log_retention_days
    noncurrent_days = 1
  }]
}

# ----------------------------------------------------------------- security group
resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  description = "Console ALB"
  vpc_id      = var.vpc_id
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each          = toset(var.allowed_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "http_redirect" {
  for_each          = toset(var.allowed_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTP (redirect to HTTPS only)"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To ECS tasks"
  referenced_security_group_id = var.app_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = var.container_port
  to_port                      = var.container_port
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = var.app_security_group_id
  description                  = "Console port from the ALB"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = var.container_port
  to_port                      = var.container_port
}

# -------------------------------------------------------------------------- ALB
resource "aws_lb" "this" {
  name                       = "${var.name_prefix}-alb"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 60

  access_logs {
    bucket  = module.logs.id
    prefix  = "alb"
    enabled = true
  }

  depends_on = [module.logs]
}

resource "aws_lb_target_group" "web" {
  name                 = "${var.name_prefix}-web"
  port                 = var.container_port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30

  health_check {
    path                = var.health_check_path
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Second target group for the mailview host; the ECS web service registers in both.
resource "aws_lb_target_group" "mailview" {
  name                 = "${var.name_prefix}-mailview"
  port                 = var.container_port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30

  health_check {
    path                = var.health_check_path
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06" # TLS 1.2 minimum, 1.3 preferred
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_certificate" "mailview" {
  count           = var.mailview_certificate_arn != null ? 1 : 0
  listener_arn    = aws_lb_listener.https.arn
  certificate_arn = var.mailview_certificate_arn
}

resource "aws_lb_listener_rule" "console" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
  condition {
    host_header {
      values = [var.domain_name]
    }
  }
}

resource "aws_lb_listener_rule" "mailview" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 200
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mailview.arn
  }
  condition {
    host_header {
      values = [var.mailview_domain_name]
    }
  }
  condition {
    path_pattern {
      values = var.mailview_path_patterns
    }
  }
}

# ---------------------------------------------------------------------------- WAF
resource "aws_wafv2_ip_set" "allowlist" {
  count              = length(var.waf_ip_allowlist) > 0 ? 1 : 0
  name               = "${var.name_prefix}-allowlist"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.waf_ip_allowlist
}

locals {
  managed_groups = {
    common        = { name = "AWSManagedRulesCommonRuleSet", priority = 20 }
    known-bad     = { name = "AWSManagedRulesKnownBadInputsRuleSet", priority = 30 }
    sqli          = { name = "AWSManagedRulesSQLiRuleSet", priority = 40 }
    ip-reputation = { name = "AWSManagedRulesAmazonIpReputationList", priority = 50 }
  }
}

resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name_prefix}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Optional allowlist: block everything outside the listed CIDRs.
  dynamic "rule" {
    for_each = length(var.waf_ip_allowlist) > 0 ? [1] : []
    content {
      name     = "block-not-allowlisted"
      priority = 0
      action {
        block {}
      }
      statement {
        not_statement {
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.allowlist[0].arn
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "block-not-allowlisted"
        sampled_requests_enabled   = true
      }
    }
  }

  # Strict limit on login/OIDC paths.
  rule {
    name     = "rate-limit-auth"
    priority = 5
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.auth_rate_limit_per_5min
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = var.auth_path_prefix
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-auth"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit-global"
    priority = 10
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-global"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.managed_groups
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# WAF logs -> KMS-encrypted log group (name MUST start with aws-waf-logs-).
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
}

data "aws_iam_policy_document" "waf_log_delivery" {
  statement {
    sid       = "AllowLogDelivery"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.waf.arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  policy_name     = "${var.name_prefix}-waf-log-delivery"
  policy_document = data.aws_iam_policy_document.waf_log_delivery.json
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
