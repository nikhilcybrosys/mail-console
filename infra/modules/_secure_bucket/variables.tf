variable "name" {
  description = "Globally unique bucket name."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for SSE-KMS. null = SSE-S3 (only for ALB access logs, which cannot use KMS)."
  type        = string
  default     = null
}

variable "object_lock" {
  description = "null = no Object Lock. Otherwise default retention; set exactly one of days/years."
  type = object({
    mode  = string
    days  = optional(number)
    years = optional(number)
  })
  default = null
}

variable "lifecycle_rules" {
  description = "Expiry rules per prefix. expiration_days = null keeps current versions forever."
  type = list(object({
    id              = string
    prefix          = optional(string, "")
    expiration_days = optional(number)
    noncurrent_days = optional(number, 30)
  }))
  default = []
}

variable "extra_policy_json" {
  description = "Extra bucket-policy documents (service principals etc.) merged with the baseline."
  type        = list(string)
  default     = []
}

variable "force_destroy" {
  description = "Never true on Object Lock buckets (locked versions cannot be deleted)."
  type        = bool
  default     = false
}

variable "enforce_key_id" {
  description = "Also deny uploads that name a different KMS key. Off for the CloudTrail bucket (unverified how CloudTrail formats the key id)."
  type        = bool
  default     = true
}
