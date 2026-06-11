terraform {
  required_version = ">= 1.3"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "harbor-live-test"
      Purpose   = "dfir-collector-testing"
      Ephemeral = "true"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

resource "random_id" "suffix" { byte_length = 4 }

# ---------------------------------------------------------------------------
# Networking — VPC with Flow Logs to CloudWatch. No NAT gateway (cost).
# ---------------------------------------------------------------------------
resource "aws_vpc" "test" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "harbor-test-vpc" }
}

resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags   = { Name = "harbor-test-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.test.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "harbor-test-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.test.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.test.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/harbor-test/vpc-flow-logs"
  retention_in_days = 1
}

resource "aws_iam_role" "flow" {
  name = "harbor-test-flowlogs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow" {
  name = "harbor-test-flowlogs-policy"
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream", "logs:PutLogEvents",
        "logs:DescribeLogGroups", "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "test" {
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_cloudwatch_log_group.flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.test.id
}

# Intentional misconfig: SSH open to the world. Flagged by the ec2 + config collectors.
resource "aws_security_group" "open" {
  name        = "harbor-test-open-sg"
  description = "Intentionally open for DFIR testing"
  vpc_id      = aws_vpc.test.id
  ingress {
    description = "SSH from anywhere (intentional misconfig)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "harbor-test-open-sg" }
}

# ---------------------------------------------------------------------------
# EC2 + EBS — user-data carries a FAKE secret; snapshot feeds the share trail.
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

resource "aws_instance" "test" {
  count                  = var.create_ec2 ? 1 : 0
  ami                    = data.aws_ami.al2023[0].id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.open.id]

  user_data = <<-EOF
    #!/bin/bash
    # FAKE bootstrap secrets for DFIR testing — not real credentials.
    export DB_PASSWORD="FAKE-do-not-use-2f8a1c"
    export API_TOKEN="FAKE-token-9b3e7d"
    # Generate a little egress so the VPC flow logs have records.
    for i in $(seq 1 6); do curl -s https://aws.amazon.com > /dev/null || true; sleep 5; done
  EOF

  tags = { Name = "harbor-test-instance" }
}

resource "aws_ebs_volume" "test" {
  count             = var.create_ec2 ? 1 : 0
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  tags              = { Name = "harbor-test-volume" }
}

resource "aws_ebs_snapshot" "test" {
  count     = var.create_ec2 ? 1 : 0
  volume_id = aws_ebs_volume.test[0].id
  tags      = { Name = "harbor-test-snapshot" }
}

# ---------------------------------------------------------------------------
# S3 — a logs bucket, a public-access-block-disabled bucket, a PII bucket.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  bucket        = "harbor-test-${random_id.suffix.hex}-logs"
  force_destroy = true
}

resource "aws_s3_bucket" "misconfig" {
  bucket        = "harbor-test-${random_id.suffix.hex}-public"
  force_destroy = true
}

# Misconfig: public access block fully disabled (the s3 collector flags this).
resource "aws_s3_bucket_public_access_block" "misconfig" {
  bucket                  = aws_s3_bucket.misconfig.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Optional, off by default: an actual anonymous public-read policy (real exposure).
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

resource "aws_s3_bucket" "pii" {
  bucket        = "harbor-test-${random_id.suffix.hex}-pii"
  force_destroy = true
}

resource "aws_s3_object" "pii" {
  bucket = aws_s3_bucket.pii.id
  key    = "customers.csv"
  source = "${path.module}/pii_sample.csv"
  etag   = filemd5("${path.module}/pii_sample.csv")
}

# ---------------------------------------------------------------------------
# KMS + Secrets Manager
# ---------------------------------------------------------------------------
resource "aws_kms_key" "test" {
  description             = "harbor-test customer-managed key"
  deletion_window_in_days = 7
  tags                    = { Name = "harbor-test-key" }
}

resource "aws_kms_alias" "test" {
  name          = "alias/harbor-test-${random_id.suffix.hex}"
  target_key_id = aws_kms_key.test.key_id
}

resource "aws_secretsmanager_secret" "test" {
  name                    = "harbor-test-secret-${random_id.suffix.hex}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "test" {
  secret_id     = aws_secretsmanager_secret.test.id
  secret_string = jsonencode({ username = "svc", password = "FAKE-not-real" })
}

# ---------------------------------------------------------------------------
# Lambda — secret-looking env vars (collector redacts) + optional public invoke.
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
  name = "harbor-test-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "test" {
  function_name    = "harbor-test-fn-${random_id.suffix.hex}"
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
}

resource "aws_lambda_permission" "public" {
  count         = var.make_lambda_public ? 1 : 0
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.test.function_name
  principal     = "*"
}

# ---------------------------------------------------------------------------
# IAM — a user with an over-broad inline policy + access key, an assumable role.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "test" {
  name          = "harbor-test-user-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_iam_access_key" "test" {
  user = aws_iam_user.test.name
}

resource "aws_iam_user_policy" "test" {
  name = "harbor-test-inline"
  user = aws_iam_user.test.name
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
  name = "harbor-test-app-role-${random_id.suffix.hex}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_caller_identity.current.account_id }
      Action    = "sts:AssumeRole"
    }]
  })
}
