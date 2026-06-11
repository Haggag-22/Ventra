# Optional AWS Config recorder + delivery channel. Gated by var.enable_config (default false)
# because it adds per-configuration-item cost and an S3 bucket. When enabled, the `config`
# collector reports an active recorder instead of a "not enabled" gap.

resource "aws_s3_bucket" "config" {
  count         = var.enable_config ? 1 : 0
  bucket        = "harbor-test-${random_id.suffix.hex}-config"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config[0].arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0
  name  = "harbor-test-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "test" {
  count    = var.enable_config ? 1 : 0
  name     = "harbor-test-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group { all_supported = true }
}

resource "aws_config_delivery_channel" "test" {
  count          = var.enable_config ? 1 : 0
  name           = "harbor-test-channel"
  s3_bucket_name = aws_s3_bucket.config[0].bucket
  depends_on     = [aws_config_configuration_recorder.test]
}

resource "aws_config_configuration_recorder_status" "test" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.test[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.test]
}
