variable "name_prefix" {
  type = string
}

variable "name" {
  description = "Short name, e.g. ses-events."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK (events key) for the topic and both queues."
  type        = string
}

variable "publisher_policy_json" {
  description = "IAM policy document JSON with the statements that let the publisher (e.g. SES) publish to the topic. The topic ARN is name_prefix-name in this account/region."
  type        = string
  default     = null
}

variable "visibility_timeout_seconds" {
  description = "Must exceed the worker's per-batch processing time."
  type        = number
  default     = 120
}
