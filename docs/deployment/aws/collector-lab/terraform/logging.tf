resource "aws_cloudtrail" "lab" {
  name                          = "${var.project}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  tags                          = { Collector = "cloudtrail" }

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

# AWS Config recorder already exists in this account (limit: 1). The config collector
# reads the account-wide recorder — no additional recorder is provisioned here.
