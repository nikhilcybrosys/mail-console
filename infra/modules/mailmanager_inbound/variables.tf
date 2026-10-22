variable "name_prefix" {
  type = string
}

variable "enable_inbound" {
  description = "Create ingress point, traffic policy, rule set, inbound archive and notification queue (~USD 50/month for the ingress endpoint). TODO-VERIFY Mail Manager availability in ap-south-1."
  type        = bool
  default     = true
}

variable "enable_outbound_archive" {
  description = "Create the archive that archive-enabled SES config sets (mc-archive) write sent bodies to."
  type        = bool
  default     = true
}

variable "inbound_domain" {
  description = "Dedicated inbound sub-domain accepted by the traffic policy, e.g. inbound.example.com."
  type        = string
}

variable "data_key_arn" {
  description = "Encrypts both archives and S3 raw-mail copies."
  type        = string
}

variable "events_key_arn" {
  description = "Encrypts the notification topic/queue."
  type        = string
}

variable "content_bucket_arn" {
  type = string
}

variable "content_bucket_id" {
  type = string
}

variable "inbound_retention" {
  description = "Archive retention. Mail Manager's SHORTEST option is THREE_MONTHS."
  type        = string
  default     = "THREE_MONTHS"
}

variable "outbound_retention" {
  description = "Outbound-body archive retention. Minimum THREE_MONTHS (cannot enforce the plan's 30 days; see README)."
  type        = string
  default     = "THREE_MONTHS"
}

variable "ingress_auth_mode" {
  description = "OPEN (public MX, normal for internet mail) or MTLS (only senders with a client cert from mtls_ca_pem)."
  type        = string
  default     = "OPEN"
  validation {
    condition     = contains(["OPEN", "MTLS"], var.ingress_auth_mode)
    error_message = "ingress_auth_mode must be OPEN or MTLS."
  }
}

variable "mtls_ca_pem" {
  description = "PEM CA bundle for MTLS mode (public certificate, not a secret)."
  type        = string
  default     = null
}

variable "tls_policy" {
  description = "OPTIONAL accepts plaintext SMTP from legacy senders; REQUIRED rejects them."
  type        = string
  default     = "OPTIONAL"
}

variable "max_message_size_bytes" {
  type    = number
  default = 26214400 # 25 MB
}

variable "store_raw_mail_in_s3" {
  description = "Also write the full raw message (.eml incl. attachments) to the content bucket under inbound/ so GuardDuty can scan it."
  type        = bool
  default     = true
}
