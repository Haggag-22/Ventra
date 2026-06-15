# ===========================================================================
# Log-destination buckets (S3-centric). Each log source ships here so the
# collector's content collectors have something to read.
# ===========================================================================

# --- Central archive: VPC flow logs, S3 server-access logs, Route53 Resolver --
resource "aws_s3_bucket" "log_archive" {
  bucket        = "${local.name}-log-archive"
  force_destroy = true
  tags          = { Name = "${local.name}-log-archive" }
}

resource "aws_s3_bucket_policy" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSLogDeliveryAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.log_archive.arn
      },
      {
        Sid       = "AWSLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.log_archive.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid       = "S3ServerAccessLogsWrite"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.log_archive.arn}/s3-access-logs/*"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      }
    ]
  })
}

# --- CloudTrail delivery bucket (only when logging is on) --------------------
resource "aws_s3_bucket" "cloudtrail" {
  count         = var.enable_logging ? 1 : 0
  bucket        = "${local.name}-cloudtrail"
  force_destroy = true
  tags          = { Name = "${local.name}-cloudtrail" }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_logging ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail[0].arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

# --- ALB access-log bucket --------------------------------------------------
resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${local.name}-alb-logs"
  force_destroy = true
  tags          = { Name = "${local.name}-alb-logs" }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ELBAccessLogsWrite"
        Effect    = "Allow"
        Principal = { AWS = data.aws_elb_service_account.main.arn }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${local.account_id}/*"
      },
      {
        Sid       = "ELBAccessLogsDelivery"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "ELBAccessLogsAclCheck"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# --- CloudFront standard-logging bucket (needs ACLs enabled) ----------------
resource "aws_s3_bucket" "cloudfront_logs" {
  bucket        = "${local.name}-cf-logs"
  force_destroy = true
  tags          = { Name = "${local.name}-cf-logs" }
}

resource "aws_s3_bucket_ownership_controls" "cloudfront_logs" {
  bucket = aws_s3_bucket.cloudfront_logs.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_acl" "cloudfront_logs" {
  depends_on = [aws_s3_bucket_ownership_controls.cloudfront_logs]
  bucket     = aws_s3_bucket.cloudfront_logs.id
  access_control_policy {
    owner {
      id = data.aws_canonical_user_id.current.id
    }
    # Grant the CloudFront log-delivery account write access.
    grant {
      grantee {
        type = "CanonicalUser"
        id   = local.cloudfront_log_canonical_id
      }
      permission = "FULL_CONTROL"
    }
    grant {
      grantee {
        type = "CanonicalUser"
        id   = data.aws_canonical_user_id.current.id
      }
      permission = "FULL_CONTROL"
    }
  }
}

# ===========================================================================
# Inventory / workload buckets (exercise the s3 collector + s3-access source).
# ===========================================================================

# App bucket — gets server access logging toggled by enable_logging.
resource "aws_s3_bucket" "app" {
  bucket        = "${local.name}-app"
  force_destroy = true
  tags          = { Name = "${local.name}-app" }
}

resource "aws_s3_bucket_logging" "app" {
  count         = var.enable_logging ? 1 : 0
  bucket        = aws_s3_bucket.app.id
  target_bucket = aws_s3_bucket.log_archive.id
  target_prefix = "s3-access-logs/app/"
  depends_on    = [aws_s3_bucket_policy.log_archive]
}

# Misconfig bucket — public access block fully disabled (the s3 collector flags it).
resource "aws_s3_bucket" "misconfig" {
  bucket        = "${local.name}-public"
  force_destroy = true
  tags          = { Name = "${local.name}-public" }
}

resource "aws_s3_bucket_public_access_block" "misconfig" {
  bucket                  = aws_s3_bucket.misconfig.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "misconfig_public" {
  count      = var.make_bucket_public ? 1 : 0
  bucket     = aws_s3_bucket.misconfig.id
  depends_on = [aws_s3_bucket_public_access_block.misconfig]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.misconfig.arn}/*"
    }]
  })
}

# PII bucket — synthetic data for the Macie classification path.
resource "aws_s3_bucket" "pii" {
  bucket        = "${local.name}-pii"
  force_destroy = true
  tags          = { Name = "${local.name}-pii" }
}

resource "aws_s3_object" "pii" {
  bucket = aws_s3_bucket.pii.id
  key    = "customers.csv"
  source = "${path.module}/pii_sample.csv"
  etag   = filemd5("${path.module}/pii_sample.csv")
}
