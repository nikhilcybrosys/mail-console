# ECS Fargate: web (gunicorn), worker (ingest_ses_events), sync (scheduled
# sync_ses_state). All tasks: private subnets, no public IP, non-root user, read-only
# root filesystem (writable ephemeral volume on /tmp only), secrets from Secrets
# Manager, awslogs into KMS-encrypted log groups.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id
  image      = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"

  env_list    = [for k, v in var.environment : { name = k, value = v }]
  secret_list = [for k, v in var.secrets : { name = k, valueFrom = v }]

  web_health = {
    command  = ["CMD-SHELL", "python -c \"import urllib.request;urllib.request.urlopen('http://127.0.0.1:${var.container_port}/healthz/',timeout=3)\" || exit 1"]
    interval = 30, timeout = 5, retries = 3, startPeriod = 40
  }
  worker_health = {
    command  = ["CMD-SHELL", "test $(( $(date +%s) - $(stat -c %Y /tmp/worker.heartbeat) )) -lt 180"]
    interval = 30, timeout = 5, retries = 3, startPeriod = 60
  }
}

# ------------------------------------------------------------------------- ECR
resource "aws_ecr_repository" "this" {
  name                 = "${var.name_prefix}-console"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.data_key_arn
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 30 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }
      action       = { type = "expire" }
    }]
  })
}

# --------------------------------------------------------------------- cluster
resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "svc" {
  for_each          = toset(["web", "worker", "sync"])
  name              = "/${var.name_prefix}/${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
}

# ------------------------------------------------------------- task definitions
resource "aws_ecs_task_definition" "web" {
  family                   = "${var.name_prefix}-web"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.web_cpu
  memory                   = var.web_memory
  task_role_arn            = var.web_role_arn
  execution_role_arn       = var.execution_role_arn

  runtime_platform {
    cpu_architecture        = var.cpu_architecture
    operating_system_family = "LINUX"
  }
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "web"
    image                  = local.image
    essential              = true
    command                = var.web_command
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    portMappings           = [{ containerPort = var.container_port, protocol = "tcp" }]
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    environment            = local.env_list
    secrets                = local.secret_list
    healthCheck            = local.web_health
    stopTimeout            = 30
    linuxParameters        = { initProcessEnabled = true, capabilities = { drop = ["ALL"] } }
    logConfiguration = {
      logDriver = "awslogs"
      options   = { "awslogs-group" = aws_cloudwatch_log_group.svc["web"].name, "awslogs-region" = local.region, "awslogs-stream-prefix" = "web" }
    }
  }])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name_prefix}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  task_role_arn            = var.worker_role_arn
  execution_role_arn       = var.execution_role_arn

  runtime_platform {
    cpu_architecture        = var.cpu_architecture
    operating_system_family = "LINUX"
  }
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge({
    name                   = "worker"
    image                  = local.image
    essential              = true
    command                = ["python", "manage.py", "ingest_ses_events"]
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    environment            = local.env_list
    secrets                = local.secret_list
    stopTimeout            = 60
    linuxParameters        = { initProcessEnabled = true, capabilities = { drop = ["ALL"] } }
    logConfiguration = {
      logDriver = "awslogs"
      options   = { "awslogs-group" = aws_cloudwatch_log_group.svc["worker"].name, "awslogs-region" = local.region, "awslogs-stream-prefix" = "worker" }
    }
  }, var.worker_heartbeat_healthcheck ? { healthCheck = local.worker_health } : {})])
}

resource "aws_ecs_task_definition" "sync" {
  family                   = "${var.name_prefix}-sync"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  task_role_arn            = var.worker_role_arn
  execution_role_arn       = var.execution_role_arn

  runtime_platform {
    cpu_architecture        = var.cpu_architecture
    operating_system_family = "LINUX"
  }
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "sync"
    image                  = local.image
    essential              = true
    command                = ["python", "manage.py", "sync_ses_state"]
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    environment            = local.env_list
    secrets                = local.secret_list
    linuxParameters        = { initProcessEnabled = true, capabilities = { drop = ["ALL"] } }
    logConfiguration = {
      logDriver = "awslogs"
      options   = { "awslogs-group" = aws_cloudwatch_log_group.svc["sync"].name, "awslogs-region" = local.region, "awslogs-stream-prefix" = "sync" }
    }
  }])
}

# --------------------------------------------------------------------- services
resource "aws_ecs_service" "web" {
  name                              = "web"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.web.arn
  desired_count                     = var.web_desired_count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 90
  propagate_tags                    = "SERVICE"
  enable_execute_command            = false

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.app_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.web_target_group_arn
    container_name   = "web"
    container_port   = var.container_port
  }

  # Same service, second target group: the separate mail-render host.
  load_balancer {
    target_group_arn = var.mailview_target_group_arn
    container_name   = "web"
    container_port   = var.container_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count] # owned by autoscaling
  }
}

resource "aws_ecs_service" "worker" {
  name                   = "worker"
  cluster                = aws_ecs_cluster.this.id
  task_definition        = aws_ecs_task_definition.worker.arn
  desired_count          = var.worker_min_count
  launch_type            = "FARGATE"
  propagate_tags         = "SERVICE"
  enable_execute_command = false

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.app_security_group_id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# ------------------------------------------------------------------ autoscaling
resource "aws_appautoscaling_target" "web" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.web.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.web_desired_count
  max_capacity       = var.web_max_count
}

resource "aws_appautoscaling_policy" "web_cpu" {
  name               = "${var.name_prefix}-web-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.web.service_namespace
  resource_id        = aws_appautoscaling_target.web.resource_id
  scalable_dimension = aws_appautoscaling_target.web.scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_appautoscaling_target" "worker" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.worker.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.worker_min_count
  max_capacity       = var.worker_max_count
}

# Backlog per task = visible messages / running tasks (AWS-recommended pattern).
# Min capacity >= 1 so the division is safe. Queue AGE is covered by an alarm in
# modules/observability.
resource "aws_appautoscaling_policy" "worker_backlog" {
  name               = "${var.name_prefix}-worker-backlog"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.worker.service_namespace
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value       = var.worker_backlog_per_task
    scale_in_cooldown  = 300
    scale_out_cooldown = 60

    customized_metric_specification {
      metrics {
        id          = "backlog_per_task"
        expression  = "visible / running"
        label       = "Backlog per worker task"
        return_data = true
      }
      metrics {
        id          = "visible"
        return_data = false
        metric_stat {
          stat = "Average"
          metric {
            namespace   = "AWS/SQS"
            metric_name = "ApproximateNumberOfMessagesVisible"
            dimensions {
              name  = "QueueName"
              value = var.events_queue_name
            }
          }
        }
      }
      metrics {
        id          = "running"
        return_data = false
        metric_stat {
          stat = "Average"
          metric {
            namespace   = "ECS/ContainerInsights"
            metric_name = "RunningTaskCount"
            dimensions {
              name  = "ClusterName"
              value = aws_ecs_cluster.this.name
            }
            dimensions {
              name  = "ServiceName"
              value = aws_ecs_service.worker.name
            }
          }
        }
      }
    }
  }
}

# ------------------------------------------------- scheduled sync (EventBridge)
data "aws_iam_policy_document" "scheduler_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "scheduler_run" {
  statement {
    sid       = "RunSyncTaskOnly"
    actions   = ["ecs:RunTask"]
    resources = ["${aws_ecs_task_definition.sync.arn_without_revision}:*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.this.arn]
    }
  }
  statement {
    sid       = "PassOnlyTheTwoTaskRoles"
    actions   = ["iam:PassRole"]
    resources = [var.worker_role_arn, var.execution_role_arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
  statement {
    sid       = "TagTasks"
    actions   = ["ecs:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ecs:CreateAction"
      values   = ["RunTask"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}-sync-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_trust.json
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "run-sync-task"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_run.json
}

# ponytail: runs may overlap if one takes > 5 min; the management command must take
# a DB advisory lock. Add a Step Functions wrapper only if that proves insufficient.
resource "aws_scheduler_schedule" "sync" {
  name                = "${var.name_prefix}-sync-ses-state"
  schedule_expression = var.sync_schedule

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_ecs_cluster.this.arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.sync.arn_without_revision
      launch_type         = "FARGATE"
      task_count          = 1
      propagate_tags      = "TASK_DEFINITION"

      network_configuration {
        subnets          = var.private_subnet_ids
        security_groups  = [var.app_security_group_id]
        assign_public_ip = false
      }
    }

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 300
    }
  }
}
