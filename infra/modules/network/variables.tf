variable "name_prefix" {
  type = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "az_count" {
  description = "Number of AZs (2 or 3). RDS Multi-AZ needs at least 2."
  type        = number
  default     = 2
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3."
  }
}

variable "enable_nat" {
  description = "Create one NAT gateway and open task egress on 443. Needed for OIDC provider unless you add an egress proxy. Default off."
  type        = bool
  default     = false
}

variable "interface_endpoint_services" {
  description = "Interface endpoint services (suffix after com.amazonaws.<region>.). Each service costs ~USD 8-10 per AZ per month; trim for staging."
  type        = set(string)
  default     = ["sqs", "kms", "secretsmanager", "ecr.api", "ecr.dkr", "logs", "email", "sts", "monitoring"]
}

variable "interface_endpoint_az_count" {
  description = "How many AZs get interface endpoint ENIs (<= az_count)."
  type        = number
  default     = 2
}

variable "log_kms_key_arn" {
  description = "CMK that encrypts the flow-log group (audit key)."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 90
}
