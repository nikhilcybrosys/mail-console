variable "name_prefix" {
  type = string
}

variable "data_key_arn" {
  type = string
}

variable "recovery_window_days" {
  description = "0 = delete immediately (staging only), otherwise 7-30."
  type        = number
  default     = 30
}

variable "secrets" {
  description = "name => description. Values are loaded by hand."
  type        = map(string)
  default = {
    "django-secret-key" = "Django SECRET_KEY (random 64+ chars)"
    "oidc-client"       = "JSON: {\"client_id\":\"...\",\"client_secret\":\"...\"} for your OpenID Connect provider"
    "app-db"            = "JSON: {\"username\":\"mc_app\",\"password\":\"...\"} - least-privilege DB role (INSERT-only on audit_log)"
    "alerts-webhook"    = "Slack/PagerDuty webhook URL used by the in-app alert engine"
  }
}
