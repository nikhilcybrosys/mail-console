variable "name_prefix" {
  type = string
}

variable "events_key_arn" {
  description = "Encrypts the alerts topic."
  type        = string
}

variable "audit_key_arn" {
  description = "Encrypts CloudTrail logs and the trail bucket."
  type        = string
}

variable "alert_email_addresses" {
  description = "SNS e-mail subscriptions (AWS-owned sender, NOT our SES). Each must click the confirmation link."
  type        = list(string)
  default     = []
}

variable "alert_https_endpoints" {
  description = "HTTPS subscriptions, e.g. a PagerDuty SNS integration URL. Slack needs AWS Chatbot (console-only, see README)."
  type        = list(string)
  default     = []
  sensitive   = true
}

variable "queues" {
  description = "Pipelines to watch: key => {queue_name, dlq_name}."
  type = map(object({
    queue_name = string
    dlq_name   = string
  }))
}

variable "ses_events_topic_name" {
  description = "SNS topic SES publishes to (for the no-events alarm)."
  type        = string
}

variable "cluster_name" {
  type = string
}

variable "worker_service_name" {
  type = string
}

variable "alb_arn_suffix" {
  type = string
}

variable "rds_identifier" {
  type = string
}

variable "web_acl_name" {
  type = string
}

variable "console_role_arns" {
  description = "Console role ARNs; SES write APIs from anyone else raise an alert."
  type        = list(string)
}

variable "trusted_admin_principal_arns" {
  description = "Role ARNs of the humans/pipeline that run terraform apply (excluded from the non-console-principal alert)."
  type        = list(string)
  default     = []
}

variable "s3_data_event_bucket_arns" {
  description = "Buckets whose object-level reads/writes are logged by CloudTrail (content bucket = body access)."
  type        = list(string)
  default     = []
}

variable "trail_log_retention_days" {
  type    = number
  default = 400
}

variable "enable_no_events_alarm" {
  description = "Alarm when SES publishes zero events for no_events_hours. Noisy on idle staging."
  type        = bool
  default     = true
}

variable "no_events_hours" {
  type    = number
  default = 3
}

variable "enable_config" {
  description = "AWS Config recorder + a few managed rules (USD ~3-10/month)."
  type        = bool
  default     = false
}

variable "rds_free_storage_bytes_threshold" {
  type    = number
  default = 10737418240 # 10 GiB
}

variable "rds_max_connections_threshold" {
  type    = number
  default = 150
}

variable "alb_5xx_threshold" {
  description = "5xx responses per 5 minutes."
  type        = number
  default     = 10
}

variable "waf_blocked_threshold" {
  description = "Blocked requests per 5 minutes that count as a spike."
  type        = number
  default     = 200
}

# SES reputation thresholds (fractions, plan section 6 item 8): warn 2% / 0.05%, page 4% / 0.08%.
variable "bounce_warn" {
  type    = number
  default = 0.02
}

variable "bounce_page" {
  type    = number
  default = 0.04
}

variable "complaint_warn" {
  type    = number
  default = 0.0005
}

variable "complaint_page" {
  type    = number
  default = 0.0008
}
