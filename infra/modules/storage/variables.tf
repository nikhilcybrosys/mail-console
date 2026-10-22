variable "name_prefix" {
  type = string
}

variable "data_key_arn" {
  type = string
}

variable "audit_key_arn" {
  type = string
}

variable "audit_object_lock" {
  description = "Audit bucket Object Lock default retention. COMPLIANCE cannot be shortened or removed by anyone, including root, until it expires: use GOVERNANCE + days in staging."
  type = object({
    mode  = string
    days  = optional(number)
    years = optional(number)
  })
  default = {
    mode  = "COMPLIANCE"
    years = 7
  }
}

variable "audit_expiration_days" {
  description = "Delete audit objects after this many days (must exceed the Object Lock retention)."
  type        = number
  default     = 2650 # ~7.25 years
}

variable "outbound_body_retention_days" {
  type    = number
  default = 30
}

variable "inbound_retention_days" {
  description = "Retention for inbound raw mail and attachments."
  type        = number
  default     = 90
}

variable "allow_ses_import_jobs" {
  description = "Bucket-policy statement letting SES read imports/ (suppression import jobs). TODO-VERIFY need."
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  type    = bool
  default = true
}
