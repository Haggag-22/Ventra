data "aws_caller_identity" "current" {}
data "aws_canonical_user_id" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" { state = "available" }

# Regional ELB log-delivery account — used by the ALB access-log bucket policy. Returns the
# correct account id whether the region is old (account-based) or new (service-principal).
data "aws_elb_service_account" "main" {}

resource "random_id" "suffix" { byte_length = 4 }

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name
  suffix     = random_id.suffix.hex
  prefix     = "logging-test"
  name       = "logging-test-${random_id.suffix.hex}"

  # Two AZs so the ALB, RDS subnet group, and EKS have what they require.
  az_a = data.aws_availability_zones.available.names[0]
  az_b = data.aws_availability_zones.available.names[1]

  # CloudFront standard-logging delivery canonical user (awslogsdelivery).
  cloudfront_log_canonical_id = "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
}
