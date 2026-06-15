# ===========================================================================
# TIER 1 — cheap, fast log sources. Logging toggled by var.enable_logging.
# ===========================================================================

# ---------------------------------------------------------------------------
# CloudTrail -> S3 (multi-region, management + S3 data events + Insights).
# OFF = no trail at all (the highest-value gap to detect).
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  count                         = var.enable_logging ? 1 : 0
  name                          = "${local.name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:${local.partition}:s3"]
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ---------------------------------------------------------------------------
# AWS Config recorder + delivery channel -> S3. OFF = no recorder.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "config" {
  count         = local.do_config ? 1 : 0
  bucket        = "${local.name}-config"
  force_destroy = true
  tags          = { Name = "${local.name}-config" }
}

resource "aws_s3_bucket_policy" "config" {
  count  = local.do_config ? 1 : 0
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
        Resource  = "${aws_s3_bucket.config[0].arn}/AWSLogs/${local.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_iam_role" "config" {
  count = local.do_config ? 1 : 0
  name  = "${local.name}-config-role"
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
  count      = local.do_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  count    = local.do_config ? 1 : 0
  name     = "${local.name}-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group { all_supported = true }
}

resource "aws_config_delivery_channel" "main" {
  count          = local.do_config ? 1 : 0
  name           = "${local.name}-channel"
  s3_bucket_name = aws_s3_bucket.config[0].bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = local.do_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ---------------------------------------------------------------------------
# ELB/ALB access logs -> S3. ON = access_logs enabled; OFF = LB with logging off.
# ---------------------------------------------------------------------------
resource "aws_lb" "main" {
  name               = "lt-${local.suffix}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  dynamic "access_logs" {
    for_each = var.enable_logging ? [1] : []
    content {
      bucket  = aws_s3_bucket.alb_logs.id
      prefix  = "alb"
      enabled = true
    }
  }

  tags       = { Name = "${local.name}-alb" }
  depends_on = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "ventra-logging-test"
      status_code  = "200"
    }
  }
}

# ---------------------------------------------------------------------------
# CloudFront access logs -> S3. ON = logging_config present; OFF = logging off.
# Custom origin to example.com keeps it origin-bucket/OAC free.
# ---------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  comment             = "${local.name} logging test"
  price_class         = "PriceClass_100"
  default_root_object = ""

  origin {
    domain_name = "example.com"
    origin_id   = "primary"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "primary"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  dynamic "logging_config" {
    for_each = var.enable_logging ? [1] : []
    content {
      bucket          = aws_s3_bucket.cloudfront_logs.bucket_domain_name
      include_cookies = false
      prefix          = "cloudfront/"
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags       = { Name = "${local.name}-cf" }
  depends_on = [aws_s3_bucket_acl.cloudfront_logs]
}

# ---------------------------------------------------------------------------
# Lambda — ON = role allowed to write CW Logs; OFF = logging perms stripped.
# (The log_posture collector counts /aws/lambda/ groups; the lambda collector
#  pulls function inventory + redacts the secret-looking env vars.)
# ---------------------------------------------------------------------------
data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/.lambda.zip"
  source {
    content  = "def handler(event, context):\n    return {'ok': True}\n"
    filename = "index.py"
  }
}

resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  count      = var.enable_logging ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "main" {
  function_name    = "${local.name}-fn"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      DB_PASSWORD = "FAKE-not-real"
      API_TOKEN   = "FAKE-not-real"
      LOG_LEVEL   = "INFO"
    }
  }

  tags = { Name = "${local.name}-fn" }
}

resource "aws_lambda_permission" "public" {
  count         = var.make_lambda_public ? 1 : 0
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.main.function_name
  principal     = "*"
}

# ---------------------------------------------------------------------------
# DynamoDB Streams — ON = stream_enabled; OFF = table with streams off.
# PAY_PER_REQUEST avoids provisioned-capacity cost.
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "main" {
  name         = "${local.name}-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  stream_enabled   = var.enable_logging
  stream_view_type = var.enable_logging ? "NEW_AND_OLD_IMAGES" : null

  tags = { Name = "${local.name}-table" }
}

# ---------------------------------------------------------------------------
# EC2 + EBS + snapshot — inventory + a fake user-data secret + egress source.
# ---------------------------------------------------------------------------
data "aws_ami" "al2023" {
  count       = var.create_ec2 ? 1 : 0
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "main" {
  count                  = var.create_ec2 ? 1 : 0
  ami                    = data.aws_ami.al2023[0].id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.open.id]

  user_data = <<-EOF
    #!/bin/bash
    # FAKE bootstrap secrets for DFIR testing — not real credentials.
    export DB_PASSWORD="FAKE-do-not-use-2f8a1c"
    export API_TOKEN="FAKE-token-9b3e7d"
    # A little egress so VPC flow logs have records.
    for i in $(seq 1 6); do curl -s https://aws.amazon.com > /dev/null || true; sleep 5; done
  EOF

  tags = { Name = "${local.name}-instance" }
}

resource "aws_ebs_volume" "main" {
  count             = var.create_ec2 ? 1 : 0
  availability_zone = local.az_a
  size              = 1
  tags              = { Name = "${local.name}-volume" }
}

resource "aws_ebs_snapshot" "main" {
  count     = var.create_ec2 ? 1 : 0
  volume_id = aws_ebs_volume.main[0].id
  tags      = { Name = "${local.name}-snapshot" }
}

# ---------------------------------------------------------------------------
# KMS + Secrets Manager (inventory collectors).
# ---------------------------------------------------------------------------
resource "aws_kms_key" "main" {
  description             = "${local.name} customer-managed key"
  deletion_window_in_days = 7
  tags                    = { Name = "${local.name}-key" }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_secretsmanager_secret" "main" {
  name                    = "${local.name}-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "main" {
  secret_id     = aws_secretsmanager_secret.main.id
  secret_string = jsonencode({ username = "svc", password = "FAKE-not-real" })
}

# ---------------------------------------------------------------------------
# IAM — user with over-broad inline policy + access key, plus an assumable role.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "main" {
  name          = "${local.name}-user"
  force_destroy = true
}

resource "aws_iam_access_key" "main" {
  user = aws_iam_user.main.name
}

resource "aws_iam_user_policy" "main" {
  name = "${local.name}-inline"
  user = aws_iam_user.main.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "iam:PassRole"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "app" {
  name = "${local.name}-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.account_id }
      Action    = "sts:AssumeRole"
    }]
  })
}
