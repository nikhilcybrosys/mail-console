output "outbound_archive_arn" {
  description = "Pass to ses_pipeline.outbound_archive_arn."
  value       = try(aws_mailmanager_archive.outbound[0].arn, null)
}

output "inbound_archive_arn" {
  value = try(aws_mailmanager_archive.inbound[0].arn, null)
}

output "archive_arns" {
  description = "Archives the web role may search."
  value       = compact([try(aws_mailmanager_archive.inbound[0].arn, ""), try(aws_mailmanager_archive.outbound[0].arn, "")])
}

output "ingress_point_a_record" {
  description = "Create:  <inbound_domain>. MX 10 <this value>.  (DNS is not managed by Terraform.)"
  value       = try(aws_mailmanager_ingress_point.inbound[0].a_record, null)
}

output "queue_arn" {
  value = try(module.events[0].queue_arn, null)
}

output "queue_arns" {
  value = compact([try(module.events[0].queue_arn, "")])
}

output "queue_name" {
  value = try(module.events[0].queue_name, null)
}

output "dlq_name" {
  value = try(module.events[0].dlq_name, null)
}

output "queue_url" {
  value = try(module.events[0].queue_url, null)
}
