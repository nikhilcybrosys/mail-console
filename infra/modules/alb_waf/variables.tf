variable "name_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "app_security_group_id" {
  description = "ECS task SG; gets an ingress rule from the ALB SG."
  type        = string
}

variable "log_kms_key_arn" {
  description = "Encrypts the WAF log group (audit key)."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate (issued by a human, DNS-validated) for the console domain. Must be in the same region."
  type        = string
}

variable "domain_name" {
  description = "Console host name, e.g. mail-console.example.com."
  type        = string
}

variable "mailview_domain_name" {
  description = "Separate REGISTRABLE domain that renders untrusted mail (plan section 7), e.g. mailview-example.net."
  type        = string
}

variable "mailview_certificate_arn" {
  description = "ACM certificate for the mailview domain. null = certificate_arn already covers it (SAN)."
  type        = string
  default     = null
}

variable "mailview_path_patterns" {
  description = "Only these paths are forwarded on the mailview host; everything else gets 404. App contract: render routes live under /m/."
  type        = list(string)
  default     = ["/m/*", "/healthz/"]
}

variable "container_port" {
  type    = number
  default = 8000
}

variable "health_check_path" {
  description = "App contract: must answer 200 for ANY Host header (ALB checks use the target IP)."
  type        = string
  default     = "/healthz/"
}

variable "allowed_ingress_cidrs" {
  description = "Who can reach the ALB on 80/443 at the network layer. 0.0.0.0/0 relies on WAF + SSO; use office/VPN CIDRs to lock it down."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "waf_ip_allowlist" {
  description = "Optional extra layer: if non-empty, WAF blocks every request not from these CIDRs."
  type        = list(string)
  default     = []
}

variable "rate_limit_per_5min" {
  description = "Per-IP request limit (5 min window) for the whole site."
  type        = number
  default     = 2000
}

variable "auth_rate_limit_per_5min" {
  description = "Stricter per-IP limit on the login/OIDC paths."
  type        = number
  default     = 100
}

variable "auth_path_prefix" {
  type    = string
  default = "/auth/"
}

variable "deletion_protection" {
  type    = bool
  default = false
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "access_log_retention_days" {
  type    = number
  default = 90
}
