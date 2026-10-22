variable "name_prefix" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "app_security_group_id" {
  type = string
}

variable "data_key_arn" {
  description = "Encrypts the ECR repository."
  type        = string
}

variable "log_kms_key_arn" {
  description = "Encrypts the log groups (audit key)."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "web_role_arn" {
  type = string
}

variable "worker_role_arn" {
  description = "Task role for the worker AND the scheduled sync task."
  type        = string
}

variable "execution_role_arn" {
  type = string
}

variable "web_target_group_arn" {
  type = string
}

variable "mailview_target_group_arn" {
  type = string
}

variable "image_tag" {
  description = "Immutable image tag to deploy (ECR tags are immutable, e.g. a git SHA)."
  type        = string
}

variable "cpu_architecture" {
  description = "X86_64 or ARM64 - must match the image build."
  type        = string
  default     = "X86_64"
}

variable "container_port" {
  type    = number
  default = 8000
}

variable "environment" {
  description = "Non-secret env vars for all containers (regions, bucket names, queue URLs, DB host...)."
  type        = map(string)
}

variable "secrets" {
  description = "Env var name => Secrets Manager valueFrom (ARN or ARN:json-key::). Injected by the execution role."
  type        = map(string)
}

variable "web_command" {
  type    = list(string)
  default = ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--access-logfile", "-"]
}

variable "web_cpu" {
  type    = number
  default = 512
}

variable "web_memory" {
  type    = number
  default = 1024
}

variable "web_desired_count" {
  type    = number
  default = 2
}

variable "web_max_count" {
  type    = number
  default = 4
}

variable "worker_cpu" {
  type    = number
  default = 256
}

variable "worker_memory" {
  type    = number
  default = 512
}

variable "worker_min_count" {
  type    = number
  default = 1
}

variable "worker_max_count" {
  type    = number
  default = 5
}

variable "worker_backlog_per_task" {
  description = "Target ApproximateNumberOfMessagesVisible per running worker task."
  type        = number
  default     = 200
}

variable "worker_heartbeat_healthcheck" {
  description = "App contract: the worker touches /tmp/worker.heartbeat at least every 60 s. Leave false until the app does."
  type        = bool
  default     = false
}

variable "events_queue_name" {
  description = "SQS queue the worker scales on."
  type        = string
}

variable "sync_schedule" {
  type    = string
  default = "rate(5 minutes)"
}
