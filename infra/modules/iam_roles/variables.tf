variable "name_prefix" {
  type = string
}

variable "allowed_regions" {
  description = "Regions in which the console roles may call SES (aws:RequestedRegion). Add regions here when the console grows."
  type        = list(string)
  default     = ["ap-south-1"]
}

variable "allowed_email_domain" {
  description = "Acting users' e-mail domain; sts:SourceIdentity must match *@<domain> for every write-role session."
  type        = string
}

variable "events_key_arn" {
  type = string
}

variable "data_key_arn" {
  type = string
}

variable "audit_key_arn" {
  type = string
}

variable "queue_arns" {
  description = "SQS queues the worker consumes (ses-events and, if enabled, inbound)."
  type        = list(string)
}

variable "content_bucket_arn" {
  type = string
}

variable "audit_bucket_arn" {
  type = string
}

variable "archive_arns" {
  description = "Mail Manager archive ARNs the web role may search. Empty = statement omitted."
  type        = list(string)
  default     = []
}

variable "ecr_repository_arn" {
  type = string
}

variable "secret_arns" {
  description = "Secrets Manager secrets injected into tasks (execution role reads them)."
  type        = list(string)
}
