output "topic_arn" {
  value = module.events.topic_arn
}

output "topic_name" {
  value = module.events.topic_name
}

output "queue_arn" {
  value = module.events.queue_arn
}

output "queue_url" {
  value = module.events.queue_url
}

output "queue_name" {
  value = module.events.queue_name
}

output "dlq_arn" {
  value = module.events.dlq_arn
}

output "dlq_name" {
  value = module.events.dlq_name
}

output "configuration_set_names" {
  value = local.set_names
}

output "firehose_stream_name" {
  value = aws_kinesis_firehose_delivery_stream.raw.name
}

output "raw_events_bucket_arn" {
  value = module.raw_events.arn
}

output "events_key_arn" {
  value = var.events_key_arn
}
