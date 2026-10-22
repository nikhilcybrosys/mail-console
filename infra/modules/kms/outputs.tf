output "events_key_arn" {
  value = aws_kms_key.events.arn
}

output "events_key_id" {
  value = aws_kms_key.events.key_id
}

output "data_key_arn" {
  value = aws_kms_key.data.arn
}

output "data_key_id" {
  value = aws_kms_key.data.key_id
}

output "audit_key_arn" {
  value = aws_kms_key.audit.arn
}

output "audit_key_id" {
  value = aws_kms_key.audit.key_id
}
