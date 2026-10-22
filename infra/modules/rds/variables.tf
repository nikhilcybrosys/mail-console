variable "name_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "app_security_group_id" {
  description = "ECS task SG: the ONLY source allowed to reach port 5432."
  type        = string
}

variable "data_key_arn" {
  description = "Encrypts storage, Performance Insights, the managed master secret and log groups' source data."
  type        = string
}

variable "log_kms_key_arn" {
  description = "Encrypts the RDS CloudWatch log groups (audit key)."
  type        = string
}

variable "multi_az" {
  description = "true in production, false in staging."
  type        = bool
  default     = false
}

variable "instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "allocated_storage_gb" {
  type    = number
  default = 50
}

variable "max_allocated_storage_gb" {
  type    = number
  default = 200
}

variable "backup_retention_days" {
  description = "PITR window."
  type        = number
  default     = 14
}

variable "deletion_protection" {
  description = "true in production."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  type    = number
  default = 90
}
