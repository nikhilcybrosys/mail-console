# Secret SHELLS only. Terraform creates the containers (name, KMS key, recovery window);
# the VALUES are put in out of band (aws secretsmanager put-secret-value) so they never
# enter Terraform state, the repo or chat. See README "Secrets to load by hand".

resource "aws_secretsmanager_secret" "this" {
  for_each                = var.secrets
  name                    = "${var.name_prefix}/${each.key}"
  description             = each.value
  kms_key_id              = var.data_key_arn
  recovery_window_in_days = var.recovery_window_days
}
