variable "name_prefix" {
  description = "Resource name prefix, e.g. mc-prod."
  type        = string
}

variable "deletion_window_days" {
  description = "Waiting period before a scheduled key deletion takes effect (7-30)."
  type        = number
  default     = 30
}
