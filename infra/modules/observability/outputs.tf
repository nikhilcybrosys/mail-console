output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "trail_bucket_arn" {
  value = module.trail_bucket.arn
}
