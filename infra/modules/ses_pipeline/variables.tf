variable "name_prefix" {
  type = string
}

variable "events_key_arn" {
  description = "events CMK: SNS, SQS, Firehose stream and the raw-events bucket."
  type        = string
}

variable "configuration_sets" {
  description = "Configuration sets to create. archive = true attaches the Mail Manager outbound archive (opted-in body categories)."
  type = map(object({
    archive = optional(bool, false)
  }))
  default = {
    "mc-default" = {}
    "mc-archive" = { archive = true }
  }
}

variable "outbound_archive_arn" {
  description = "Mail Manager archive for outbound bodies. null = archive-enabled sets are NOT created."
  type        = string
  default     = null
}

variable "tls_policy" {
  description = "REQUIRE drops mail to servers without TLS; OPTIONAL is the SES default."
  type        = string
  default     = "OPTIONAL"
}

variable "suppressed_reasons" {
  type    = list(string)
  default = ["BOUNCE", "COMPLAINT"]
}

variable "enable_vdm" {
  description = "Account-level Virtual Deliverability Manager (needed for GetMessageInsights; ~USD 0.07 per 1000 mails)."
  type        = bool
  default     = false
}

variable "raw_events_object_lock" {
  description = "Object Lock default retention of the raw-events bucket (13 months = 396 days)."
  type = object({
    mode  = string
    days  = optional(number)
    years = optional(number)
  })
  default = {
    mode = "COMPLIANCE"
    days = 396
  }
}

variable "raw_events_expiration_days" {
  description = "Delete raw events after this many days (must exceed the Object Lock retention)."
  type        = number
  default     = 400
}

variable "manage_identities" {
  description = "false (default): Terraform does not touch SES identities. true: manage the identities below (import existing ones first, see README)."
  type        = bool
  default     = false
}

variable "identities" {
  description = "Identities to manage when manage_identities = true. Key = identity (domain or address)."
  type = map(object({
    default_configuration_set = optional(string, "mc-default")
    mail_from_domain          = optional(string)
    dkim_key_length           = optional(string, "RSA_2048_BIT")
  }))
  default = {}
}
