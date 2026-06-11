###############################################################################
# Harbor — reference forensics environment.
# Isolated analysis VPC (no IGW) + immutable evidence bucket + duty-separated roles.
# REVIEW before applying. See README.md.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "evidence_bucket_name" {
  type        = string
  description = "Globally-unique name for the immutable evidence bucket."
  default     = "harbor-forensics-evidence-CHANGE-ME"
}

variable "object_lock_days" {
  type        = number
  description = "Retention period (days) for evidence under Object Lock compliance mode."
  default     = 365
}

provider "aws" {
  region = var.region
}

# --- Isolated forensics VPC (no internet gateway) ----------------------------

resource "aws_vpc" "forensics" {
  cidr_block           = "10.90.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "harbor-forensics", Purpose = "dfir" }
}

resource "aws_subnet" "analysis" {
  vpc_id            = aws_vpc.forensics.id
  cidr_block        = "10.90.1.0/24"
  availability_zone = "${var.region}a"
  tags              = { Name = "harbor-forensics-analysis" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.forensics.id
  tags   = { Name = "harbor-forensics-private" }
  # Intentionally no 0.0.0.0/0 route — the environment has no internet egress.
}

resource "aws_route_table_association" "analysis" {
  subnet_id      = aws_subnet.analysis.id
  route_table_id = aws_route_table.private.id
}

# S3 reached via a gateway endpoint, not the internet.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.forensics.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# Restrictive SG: no inbound; egress only to the S3 prefix list.
resource "aws_security_group" "analysis" {
  name        = "harbor-forensics-analysis"
  description = "No inbound; egress only to S3 via the gateway endpoint."
  vpc_id      = aws_vpc.forensics.id

  egress {
    description     = "S3 via gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }
  tags = { Name = "harbor-forensics-analysis" }
}

# Log our own investigative activity.
resource "aws_flow_log" "forensics" {
  vpc_id          = aws_vpc.forensics.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/harbor/forensics/flowlogs"
  retention_in_days = 365
}

# --- Immutable evidence bucket -----------------------------------------------

resource "aws_s3_bucket" "evidence" {
  bucket              = var.evidence_bucket_name
  object_lock_enabled = true
  tags                = { Purpose = "dfir-evidence" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
    bucket_key_enabled = true
  }
}

# --- Roles modelling separation of duties ------------------------------------

data "aws_caller_identity" "me" {}

locals {
  trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "responder" {
  name               = "harbor-responder"
  assume_role_policy = local.trust
  description        = "Acquires evidence (runs the collector in source accounts)."
}

resource "aws_iam_role" "investigator" {
  name               = "harbor-investigator"
  assume_role_policy = local.trust
  description        = "Analyzes evidence in the forensics account."
}

resource "aws_iam_role" "custodian" {
  name               = "harbor-data-custodian"
  assume_role_policy = local.trust
  description        = "Manages the evidence bucket lifecycle."
}

resource "aws_iam_role" "flow_logs" {
  name = "harbor-forensics-flowlogs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

output "evidence_bucket" { value = aws_s3_bucket.evidence.bucket }
output "forensics_vpc_id" { value = aws_vpc.forensics.id }
