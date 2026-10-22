output "arns" {
  description = "name => secret ARN."
  value       = { for k, v in aws_secretsmanager_secret.this : k => v.arn }
}

output "arn_list" {
  value = [for v in aws_secretsmanager_secret.this : v.arn]
}
