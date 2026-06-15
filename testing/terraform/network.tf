# ---------------------------------------------------------------------------
# VPC + two public subnets (ALB / RDS / EKS need >=2 AZs) + a firewall subnet.
# No NAT gateway — that's the big hidden cost. Subnets/IGW/route tables are free.
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "${local.name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = local.az_a
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.2.0/24"
  availability_zone       = local.az_b
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-public-b" }
}

# Dedicated subnet for the Tier 3 Network Firewall endpoint (free until the firewall exists).
resource "aws_subnet" "firewall" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.3.0/24"
  availability_zone = local.az_a
  tags              = { Name = "${local.name}-firewall" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${local.name}-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

# Intentional misconfig: SSH open to the world. Flagged by the ec2/config collectors.
resource "aws_security_group" "open" {
  name        = "${local.name}-open-sg"
  description = "Intentionally open for DFIR testing"
  vpc_id      = aws_vpc.main.id

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

  tags = { Name = "${local.name}-open-sg" }
}

# ALB security group — HTTP in from anywhere.
resource "aws_security_group" "alb" {
  name        = "${local.name}-alb-sg"
  description = "ALB ingress for access-log testing"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-alb-sg" }
}

# ---------------------------------------------------------------------------
# VPC Flow Logs -> S3 (S3-centric, per the locked decision). Gated by enable_logging:
# ON  = flow log attached to the VPC; OFF = VPC with no flow log (a gap to detect).
# ---------------------------------------------------------------------------
resource "aws_flow_log" "main" {
  count                = var.enable_logging ? 1 : 0
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.log_archive.arn}/vpc-flow-logs/"
  depends_on           = [aws_s3_bucket_policy.log_archive]
}
