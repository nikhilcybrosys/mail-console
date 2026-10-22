variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "name_prefix" {
  type    = string
  default = "mc-prod"
}

variable "aws_account_id" {
  description = "The NEW dedicated mail-console account. The provider refuses any other account."
  type        = string
}

variable "ses_regions" {
  description = "Regions the console roles may call SES in."
  type        = list(string)
  default     = ["ap-south-1"]
}

variable "allowed_email_domain" {
  description = "Acting users' e-mail domain; sts:SourceIdentity must match *@<domain> for every write-role session."
  type        = string
}

# ---- network
variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "az_count" {
  type    = number
  default = 2
}

variable "enable_nat" {
  description = "Needed for OIDC provider egress (no PrivateLink exists). Production default on; see README decision D1."
  type        = bool
  default     = true
}

variable "interface_endpoint_services" {
  type    = set(string)
  default = ["sqs", "kms", "secretsmanager", "ecr.api", "ecr.dkr", "logs", "email", "sts", "monitoring"]
}

variable "interface_endpoint_az_count" {
  type    = number
  default = 2
}

# ---- domains / certs (human input)
variable "domain_name" {
  description = "Console host name, e.g. mail-console.example.com"
  type        = string
}

variable "mailview_domain_name" {
  description = "Separate registrable domain for rendering mail."
  type        = string
}

variable "inbound_domain" {
  description = "Inbound MX sub-domain, e.g. inbound.example.com"
  type        = string
}

variable "certificate_arn" {
  description = "Issued ACM certificate for domain_name (same region)."
  type        = string
}

variable "mailview_certificate_arn" {
  description = "ACM certificate for mailview_domain_name; null if certificate_arn has it as a SAN."
  type        = string
  default     = null
}

variable "allowed_ingress_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "waf_ip_allowlist" {
  type    = list(string)
  default = []
}

# ---- app
variable "image_tag" {
  description = "Immutable ECR image tag (git SHA)."
  type        = string
}

variable "web_desired_count" {
  type    = number
  default = 2
}

# ---- SES / mail
variable "enable_vdm" {
  type    = bool
  default = false
}

variable "enable_inbound" {
  description = "Mail Manager ingress point (~USD 50/month)."
  type        = bool
  default     = true
}

variable "enable_outbound_archive" {
  type    = bool
  default = true
}

variable "inbound_archive_retention" {
  type    = string
  default = "THREE_MONTHS"
}

variable "outbound_archive_retention" {
  type    = string
  default = "THREE_MONTHS"
}

variable "ingress_auth_mode" {
  type    = string
  default = "OPEN"
}

variable "mtls_ca_pem" {
  type    = string
  default = null
}

variable "manage_identities" {
  type    = bool
  default = false
}

variable "identities" {
  type = map(object({
    default_configuration_set = optional(string, "mc-default")
    mail_from_domain          = optional(string)
    dkim_key_length           = optional(string, "RSA_2048_BIT")
  }))
  default = {}
}

# ---- retention / immutability
variable "audit_object_lock" {
  description = "COMPLIANCE 7 years: IRREVERSIBLE, even root cannot delete or shorten. Decision D3."
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
  type    = number
  default = 2650
}

variable "raw_events_object_lock" {
  type = object({
    mode  = string
    days  = optional(number)
    years = optional(number)
  })
  default = {
    mode = "COMPLIANCE"
    days = 396 # 13 months
  }
}

variable "raw_events_expiration_days" {
  type    = number
  default = 400
}

variable "outbound_body_retention_days" {
  type    = number
  default = 30
}

variable "inbound_retention_days" {
  type    = number
  default = 90
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "secret_recovery_window_days" {
  type    = number
  default = 30
}

# ---- database / load balancer
variable "rds_multi_az" {
  type    = bool
  default = true
}

variable "rds_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "rds_deletion_protection" {
  type    = bool
  default = true
}

variable "alb_deletion_protection" {
  type    = bool
  default = true
}

# ---- alerting
variable "alert_email_addresses" {
  type    = list(string)
  default = []
}

variable "alert_https_endpoints" {
  type      = list(string)
  default   = []
  sensitive = true
}

variable "trusted_admin_principal_arns" {
  description = "Role ARNs that run terraform apply (excluded from the non-console SES-write alert)."
  type        = list(string)
  default     = []
}

variable "enable_no_events_alarm" {
  type    = bool
  default = true
}

variable "enable_config" {
  type    = bool
  default = true
}

variable "oidc_discovery_url" {
  description = "OpenID Connect discovery URL of your identity provider. Use a tenant-specific URL: multi-tenant endpoints with a templated issuer are refused by the app."
  type        = string
  default     = "https://accounts.google.com/.well-known/openid-configuration"
}

variable "oidc_provider_name" {
  description = "Name shown on the sign-in button."
  type        = string
  default     = "SSO"
}
