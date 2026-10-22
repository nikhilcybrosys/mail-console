output "boundary_policy_arn" {
  value = aws_iam_policy.boundary.arn
}

output "web_role_arn" {
  value = aws_iam_role.web.arn
}

output "worker_role_arn" {
  value = aws_iam_role.worker.arn
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "write_ops_role_arn" {
  value = aws_iam_role.write_ops.arn
}

output "write_security_role_arn" {
  value = aws_iam_role.write_security.arn
}

output "console_role_arns" {
  description = "All console role ARNs (used by the CloudTrail 'non-console principal' alarm)."
  value = [
    aws_iam_role.web.arn, aws_iam_role.worker.arn, aws_iam_role.write_ops.arn,
    aws_iam_role.write_security.arn, aws_iam_role.execution.arn,
  ]
}
