resource "aws_cloudtrail" "lab" {
  name                          = "${var.project}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  tags                          = merge(local.common_tags, { Collector = "cloudtrail" })

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.sensitive.arn}/*"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# AWS Config — one recorder per region. Disable with enable_config=false if your account
# already has a recorder (AWS limit: 1 per region).
resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0
  name  = "${var.project}-config"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = merge(local.common_tags, { Collector = "config" })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "lab" {
  count    = var.enable_config ? 1 : 0
  name     = "${var.project}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "lab" {
  count          = var.enable_config ? 1 : 0
  name           = "${var.project}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  depends_on     = [aws_config_configuration_recorder.lab]
}

resource "aws_config_configuration_recorder_status" "lab" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.lab[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.lab]
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AWSConfigBucketPermissionsCheck"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = aws_s3_bucket.config.arn
    }, {
      Sid       = "AWSConfigBucketDelivery"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"
      Condition = {
        StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
      }
    }]
  })
}
