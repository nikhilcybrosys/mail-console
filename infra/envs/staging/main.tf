# Mail Console - one environment. staging and production share this file
# byte for byte; they differ only in variables.tf defaults and terraform.tfvars.

data "aws_caller_identity" "current" {}

locals {
  prefix         = var.name_prefix
  inbound_on     = var.enable_inbound
  default_set    = "mc-default"
  archive_set    = "mc-archive"
  ses_queue_arns = [module.ses_pipeline.queue_arn]
  queue_arns     = concat(local.ses_queue_arns, module.mailmanager.queue_arns)

  queues_watched = merge(
    { ses-events = { queue_name = module.ses_pipeline.queue_name, dlq_name = module.ses_pipeline.dlq_name } },
    var.enable_inbound ? { inbound = { queue_name = module.mailmanager.queue_name, dlq_name = module.mailmanager.dlq_name } } : {},
  )
}

# 1. Keys
module "kms" {
  source      = "../../modules/kms"
  name_prefix = local.prefix
}

# 2. Network (flow logs use the audit key)
module "network" {
  source                      = "../../modules/network"
  name_prefix                 = local.prefix
  vpc_cidr                    = var.vpc_cidr
  az_count                    = var.az_count
  enable_nat                  = var.enable_nat
  interface_endpoint_services = var.interface_endpoint_services
  interface_endpoint_az_count = var.interface_endpoint_az_count
  log_kms_key_arn             = module.kms.audit_key_arn
  log_retention_days          = var.log_retention_days
}

# 3. Buckets + GuardDuty malware plan
module "storage" {
  source                       = "../../modules/storage"
  name_prefix                  = local.prefix
  data_key_arn                 = module.kms.data_key_arn
  audit_key_arn                = module.kms.audit_key_arn
  audit_object_lock            = var.audit_object_lock
  audit_expiration_days        = var.audit_expiration_days
  outbound_body_retention_days = var.outbound_body_retention_days
  inbound_retention_days       = var.inbound_retention_days
}

# 4. Mail Manager (inbound + outbound archive)
module "mailmanager" {
  source                  = "../../modules/mailmanager_inbound"
  name_prefix             = local.prefix
  enable_inbound          = var.enable_inbound
  enable_outbound_archive = var.enable_outbound_archive
  inbound_domain          = var.inbound_domain
  data_key_arn            = module.kms.data_key_arn
  events_key_arn          = module.kms.events_key_arn
  content_bucket_arn      = module.storage.content_bucket_arn
  content_bucket_id       = module.storage.content_bucket_id
  inbound_retention       = var.inbound_archive_retention
  outbound_retention      = var.outbound_archive_retention
  ingress_auth_mode       = var.ingress_auth_mode
  mtls_ca_pem             = var.mtls_ca_pem
}

# 5. SES pipeline
module "ses_pipeline" {
  source                     = "../../modules/ses_pipeline"
  name_prefix                = local.prefix
  events_key_arn             = module.kms.events_key_arn
  outbound_archive_arn       = module.mailmanager.outbound_archive_arn
  enable_vdm                 = var.enable_vdm
  raw_events_object_lock     = var.raw_events_object_lock
  raw_events_expiration_days = var.raw_events_expiration_days
  manage_identities          = var.manage_identities
  identities                 = var.identities
}

# 6. Secret shells (values loaded by hand)
module "secrets" {
  source               = "../../modules/secrets"
  name_prefix          = local.prefix
  data_key_arn         = module.kms.data_key_arn
  recovery_window_days = var.secret_recovery_window_days
}

# 7. Database
module "rds" {
  source                = "../../modules/rds"
  name_prefix           = local.prefix
  vpc_id                = module.network.vpc_id
  private_subnet_ids    = module.network.private_subnet_ids
  app_security_group_id = module.network.app_security_group_id
  data_key_arn          = module.kms.data_key_arn
  log_kms_key_arn       = module.kms.audit_key_arn
  multi_az              = var.rds_multi_az
  instance_class        = var.rds_instance_class
  deletion_protection   = var.rds_deletion_protection
  backup_retention_days = 14
  log_retention_days    = var.log_retention_days
}

# 8. ALB + WAF
module "alb_waf" {
  source                    = "../../modules/alb_waf"
  name_prefix               = local.prefix
  vpc_id                    = module.network.vpc_id
  public_subnet_ids         = module.network.public_subnet_ids
  app_security_group_id     = module.network.app_security_group_id
  log_kms_key_arn           = module.kms.audit_key_arn
  certificate_arn           = var.certificate_arn
  mailview_certificate_arn  = var.mailview_certificate_arn
  domain_name               = var.domain_name
  mailview_domain_name      = var.mailview_domain_name
  allowed_ingress_cidrs     = var.allowed_ingress_cidrs
  waf_ip_allowlist          = var.waf_ip_allowlist
  deletion_protection       = var.alb_deletion_protection
  log_retention_days        = var.log_retention_days
  access_log_retention_days = var.log_retention_days
}

# 9. IAM (roles + boundary)
module "iam_roles" {
  source               = "../../modules/iam_roles"
  name_prefix          = local.prefix
  allowed_regions      = var.ses_regions
  allowed_email_domain = var.allowed_email_domain
  events_key_arn       = module.kms.events_key_arn
  data_key_arn         = module.kms.data_key_arn
  audit_key_arn        = module.kms.audit_key_arn
  queue_arns           = local.queue_arns
  content_bucket_arn   = module.storage.content_bucket_arn
  audit_bucket_arn     = module.storage.audit_bucket_arn
  archive_arns         = module.mailmanager.archive_arns
  ecr_repository_arn   = module.ecs.ecr_repository_arn
  secret_arns          = concat(module.secrets.arn_list, [module.rds.master_secret_arn])
}

# 10. ECS
module "ecs" {
  source                    = "../../modules/ecs"
  name_prefix               = local.prefix
  private_subnet_ids        = module.network.private_subnet_ids
  app_security_group_id     = module.network.app_security_group_id
  data_key_arn              = module.kms.data_key_arn
  log_kms_key_arn           = module.kms.audit_key_arn
  log_retention_days        = var.log_retention_days
  web_role_arn              = module.iam_roles.web_role_arn
  worker_role_arn           = module.iam_roles.worker_role_arn
  execution_role_arn        = module.iam_roles.execution_role_arn
  web_target_group_arn      = module.alb_waf.web_target_group_arn
  mailview_target_group_arn = module.alb_waf.mailview_target_group_arn
  image_tag                 = var.image_tag
  web_desired_count         = var.web_desired_count
  events_queue_name         = module.ses_pipeline.queue_name

  # Names below are exactly what config/settings.py reads (MC_ prefix). Keep them in sync.
  environment = {
    AWS_DEFAULT_REGION             = var.region
    MC_AWS_REGIONS                 = join(",", var.ses_regions)
    MC_SQS_EVENTS_QUEUE_URL        = module.ses_pipeline.queue_url
    MC_EXPECTED_SNS_TOPIC_ARNS     = module.ses_pipeline.topic_arn
    MC_SQS_INBOUND_QUEUE_URL       = module.mailmanager.queue_url != null ? module.mailmanager.queue_url : ""
    MC_DB_HOST                     = module.rds.address
    MC_DB_PORT                     = tostring(module.rds.port)
    MC_DB_NAME                     = module.rds.db_name
    MC_DB_SSLMODE                  = "require"
    MC_CONTENT_BUCKET              = module.storage.content_bucket_id
    MC_AUDIT_BUCKET                = module.storage.audit_bucket_id
    MC_AWS_WRITE_ROLE_OPS_ARN      = module.iam_roles.write_ops_role_arn
    MC_AWS_WRITE_ROLE_SECURITY_ARN = module.iam_roles.write_security_role_arn
    MC_CONSOLE_HOST                = var.domain_name
    MC_MAILVIEW_HOST               = var.mailview_domain_name
    MC_WEBAUTHN_RP_ID              = var.domain_name
    MC_WEBAUTHN_ORIGIN             = "https://${var.domain_name}"
    MC_OIDC_ALLOWED_DOMAIN         = var.allowed_email_domain
    MC_OIDC_DISCOVERY_URL          = var.oidc_discovery_url
    MC_OIDC_PROVIDER_NAME          = var.oidc_provider_name
  }

  secrets = {
    MC_SECRET_KEY              = module.secrets.arns["django-secret-key"]
    MC_OIDC_CLIENT_ID          = "${module.secrets.arns["oidc-client"]}:client_id::"
    MC_OIDC_CLIENT_SECRET      = "${module.secrets.arns["oidc-client"]}:client_secret::"
    MC_DB_USER                 = "${module.secrets.arns["app-db"]}:username::"
    MC_DB_PASSWORD             = "${module.secrets.arns["app-db"]}:password::"
    MC_ALERT_SLACK_WEBHOOK_URL = module.secrets.arns["alerts-webhook"]
  }
}

# 11. Alarms, CloudTrail, GuardDuty, Access Analyzer
module "observability" {
  source                       = "../../modules/observability"
  name_prefix                  = local.prefix
  events_key_arn               = module.kms.events_key_arn
  audit_key_arn                = module.kms.audit_key_arn
  alert_email_addresses        = var.alert_email_addresses
  alert_https_endpoints        = var.alert_https_endpoints
  queues                       = local.queues_watched
  ses_events_topic_name        = module.ses_pipeline.topic_name
  cluster_name                 = module.ecs.cluster_name
  worker_service_name          = module.ecs.worker_service_name
  alb_arn_suffix               = module.alb_waf.alb_arn_suffix
  rds_identifier               = module.rds.identifier
  web_acl_name                 = module.alb_waf.web_acl_name
  console_role_arns            = module.iam_roles.console_role_arns
  trusted_admin_principal_arns = var.trusted_admin_principal_arns
  s3_data_event_bucket_arns    = [module.storage.content_bucket_arn]
  enable_no_events_alarm       = var.enable_no_events_alarm
  enable_config                = var.enable_config
}
