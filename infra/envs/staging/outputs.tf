output "alb_dns_name" {
  description = "Create DNS CNAME/ALIAS records for domain_name and mailview_domain_name pointing here."
  value       = module.alb_waf.alb_dns_name
}

output "ecr_repository_url" {
  value = module.ecs.ecr_repository_url
}

output "inbound_mx_instructions" {
  description = "Human step: create this MX record (Terraform does not manage DNS)."
  value       = var.enable_inbound ? "${var.inbound_domain}.  MX  10  ${module.mailmanager.ingress_point_a_record}." : "inbound disabled (enable_inbound = false)"
}

output "ses_configuration_sets" {
  value = module.ses_pipeline.configuration_set_names
}

output "ses_events_queue_url" {
  value = module.ses_pipeline.queue_url
}

output "write_role_arns" {
  value = {
    ops      = module.iam_roles.write_ops_role_arn
    security = module.iam_roles.write_security_role_arn
  }
}

output "console_role_arns" {
  value = {
    web    = module.iam_roles.web_role_arn
    worker = module.iam_roles.worker_role_arn
  }
}

output "boundary_policy_arn" {
  value = module.iam_roles.boundary_policy_arn
}

output "secret_arns" {
  description = "Load their values by hand (README)."
  value       = module.secrets.arns
}

output "alerts_topic_arn" {
  value = module.observability.alerts_topic_arn
}

output "rds_address" {
  value = module.rds.address
}
