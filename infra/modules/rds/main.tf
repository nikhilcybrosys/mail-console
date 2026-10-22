# PostgreSQL 16 in private subnets, reachable only from the ECS task SG, TLS forced,
# encrypted with the data CMK, PITR, master password generated and rotated by RDS
# into Secrets Manager (manage_master_user_password).
#
# Cross-region snapshot copy (DR) is NOT created here: it needs a provider alias and
# a KMS key in the DR region. Add aws_db_instance_automated_backups_replication in a
# second provider region when the DR region is decided (see README, "Known gaps").

locals {
  identifier = "${var.name_prefix}-pg"
}

resource "aws_db_subnet_group" "this" {
  name       = "${local.identifier}-subnets"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "db" {
  name_prefix = "${local.identifier}-"
  description = "PostgreSQL: only from the console task SG"
  vpc_id      = var.vpc_id
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from ECS tasks"
  referenced_security_group_id = var.app_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${local.identifier}-"
  family      = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Pre-create log groups so they are KMS-encrypted and have a retention.
resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/instance/${local.identifier}/postgresql"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
}

resource "aws_cloudwatch_log_group" "upgrade" {
  name              = "/aws/rds/instance/${local.identifier}/upgrade"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
}

data "aws_iam_policy_document" "monitoring_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring" {
  name               = "${local.identifier}-enhanced-monitoring"
  assume_role_policy = data.aws_iam_policy_document.monitoring_trust.json
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "this" {
  identifier     = local.identifier
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.instance_class

  db_name  = "mailconsole"
  username = "mc_admin"

  # RDS creates, stores (KMS: data key) and rotates the master password.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.data_key_arn

  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.max_allocated_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.data_key_arn

  multi_az               = var.multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.this.name

  iam_database_authentication_enabled = true
  backup_retention_period             = var.backup_retention_days
  backup_window                       = "20:00-21:00" # 01:30-02:30 IST
  maintenance_window                  = "sun:21:30-sun:22:30"
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = !var.deletion_protection
  final_snapshot_identifier = var.deletion_protection ? "${local.identifier}-final" : null

  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.data_key_arn
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.monitoring.arn
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  depends_on = [aws_cloudwatch_log_group.postgresql, aws_cloudwatch_log_group.upgrade]

  lifecycle {
    ignore_changes = [engine_version] # minor versions auto-upgrade
  }
}
