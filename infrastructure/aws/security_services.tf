# Targets: guardduty, securityhub, config, detective, macie, inspector2, iam, account, kms, secrets

data "aws_guardduty_detector" "main" {
  count = var.use_existing_account_services ? 1 : 0
}

resource "aws_guardduty_detector" "lab" {
  count  = var.use_existing_account_services ? 0 : 1
  enable = true
  tags   = { Name = "${local.name}-guardduty" }
}

resource "aws_securityhub_account" "lab" {
  enable_default_standards = true
}

resource "aws_inspector2_enabler" "lab" {
  count          = var.enable_inspector ? 1 : 0
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]

  timeouts {
    create = "20m"
    update = "20m"
    delete = "20m"
  }
}

resource "aws_macie2_account" "lab" {
  count                        = var.enable_macie && !var.use_existing_account_services ? 1 : 0
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

resource "aws_s3_bucket" "config" {
  count         = var.use_existing_account_services ? 0 : 1
  bucket        = "${local.name}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_iam_role" "config" {
  count = var.use_existing_account_services ? 0 : 1
  name  = "${local.name}-config"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.use_existing_account_services ? 0 : 1
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "lab" {
  count    = var.use_existing_account_services ? 0 : 1
  name     = "${local.name}-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "lab" {
  count          = var.use_existing_account_services ? 0 : 1
  name           = "${local.name}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].bucket
  depends_on     = [aws_config_configuration_recorder.lab]
}

resource "aws_config_configuration_recorder_status" "lab" {
  count      = var.use_existing_account_services ? 0 : 1
  name       = aws_config_configuration_recorder.lab[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.lab]
}

resource "aws_detective_graph" "lab" {
  count = var.enable_detective ? 1 : 0
  tags  = { Name = "${local.name}-detective" }
}

resource "aws_kms_key" "lab" {
  description             = "Ventra lab CMK"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = { Name = "${local.name}-cmk" }
}

resource "aws_kms_alias" "lab" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.lab.key_id
}

resource "aws_secretsmanager_secret" "lab" {
  name       = "${local.name}/demo-secret"
  kms_key_id = aws_kms_key.lab.arn
  tags       = { Name = "${local.name}-secret" }
}

resource "aws_secretsmanager_secret_version" "lab" {
  secret_id     = aws_secretsmanager_secret.lab.id
  secret_string = "PLACEHOLDER_ROTATE_AFTER_APPLY"
}

resource "aws_iam_user" "lab_readonly" {
  name = "${local.name}-readonly-snapshot"
  tags = { Name = "${local.name}-iam-snapshot" }
}

resource "aws_iam_user_policy_attachment" "lab_readonly" {
  user       = aws_iam_user.lab_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_s3_bucket_logging" "config" {
  count         = var.use_existing_account_services ? 0 : 1
  bucket        = aws_s3_bucket.config[0].id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "config-bucket/"
}
