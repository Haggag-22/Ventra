# ===========================================================================
# TIER 3 — hourly-billed. Gated by var.enable_expensive. Stand these up ONLY
# while actively testing the row, then destroy immediately. The logging portion
# is additionally gated by var.enable_logging for the on/off matrix.
# ===========================================================================

locals {
  # Each Tier 3 service is built if its own toggle OR the enable_expensive master is on.
  want_network_firewall = var.enable_expensive || var.enable_network_firewall
  want_opensearch       = var.enable_expensive || var.enable_opensearch
  want_rds              = var.enable_expensive || var.enable_rds
  want_eks              = var.enable_expensive || var.enable_eks

  # Logging variants (only wire the destination when the service is built AND logging is on).
  netfw_with_logging      = local.want_network_firewall && var.enable_logging
  opensearch_with_logging = local.want_opensearch && var.enable_logging
}

# ---------------------------------------------------------------------------
# Network Firewall + logging -> S3.
# ---------------------------------------------------------------------------
resource "aws_networkfirewall_firewall_policy" "main" {
  count = local.want_network_firewall ? 1 : 0
  name  = "lt-${local.suffix}-fw-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  }

  tags = { Name = "${local.name}-fw-policy" }
}

resource "aws_networkfirewall_firewall" "main" {
  count               = local.want_network_firewall ? 1 : 0
  name                = "lt-${local.suffix}-fw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main[0].arn
  vpc_id              = aws_vpc.main.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }

  tags = { Name = "${local.name}-fw" }
}

resource "aws_networkfirewall_logging_configuration" "main" {
  count        = local.netfw_with_logging ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.main[0].arn

  logging_configuration {
    log_destination_config {
      log_type             = "FLOW"
      log_destination_type = "S3"
      log_destination = {
        bucketName = aws_s3_bucket.log_archive.id
        prefix     = "network-firewall"
      }
    }
  }
  depends_on = [aws_s3_bucket_policy.log_archive]
}

# ---------------------------------------------------------------------------
# OpenSearch domain + log publishing -> CloudWatch.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "opensearch" {
  count             = local.opensearch_with_logging ? 1 : 0
  name              = "/aws/opensearch/${local.name}"
  retention_in_days = 1
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  count       = local.opensearch_with_logging ? 1 : 0
  policy_name = "lt-${local.suffix}-opensearch"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "es.amazonaws.com" }
      Action    = ["logs:PutLogEvents", "logs:CreateLogStream"]
      Resource  = "${aws_cloudwatch_log_group.opensearch[0].arn}:*"
    }]
  })
}

resource "aws_opensearch_domain" "main" {
  count          = local.want_opensearch ? 1 : 0
  domain_name    = "lt-${local.suffix}"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
      Action    = "es:*"
      Resource  = "arn:${local.partition}:es:${local.region}:${local.account_id}:domain/lt-${local.suffix}/*"
    }]
  })

  dynamic "log_publishing_options" {
    for_each = local.opensearch_with_logging ? toset(["ES_APPLICATION_LOGS", "INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS"]) : toset([])
    content {
      cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch[0].arn
      log_type                 = log_publishing_options.value
    }
  }

  tags       = { Name = "${local.name}-opensearch" }
  depends_on = [aws_cloudwatch_log_resource_policy.opensearch]
}

# ---------------------------------------------------------------------------
# RDS instance + CloudWatch log exports.
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "main" {
  count      = local.want_rds ? 1 : 0
  name       = "lt-${local.suffix}-db-subnets"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags       = { Name = "${local.name}-db-subnets" }
}

resource "aws_db_instance" "main" {
  count                           = local.want_rds ? 1 : 0
  identifier                      = "lt-${local.suffix}-rds"
  engine                          = "mysql"
  engine_version                  = "8.0"
  instance_class                  = "db.t3.micro"
  allocated_storage               = 20
  username                        = "admin"
  password                        = "FAKE-not-real-Passw0rd"
  db_subnet_group_name            = aws_db_subnet_group.main[0].name
  vpc_security_group_ids          = [aws_security_group.open.id]
  skip_final_snapshot             = true
  publicly_accessible             = false
  enabled_cloudwatch_logs_exports = var.enable_logging ? ["error", "general", "slowquery"] : null
  tags                            = { Name = "${local.name}-rds" }
}

# ---------------------------------------------------------------------------
# EKS cluster + control-plane (audit) logging.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "eks" {
  count = local.want_eks ? 1 : 0
  name  = "${local.name}-eks-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  count      = local.want_eks ? 1 : 0
  role       = aws_iam_role.eks[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "main" {
  count    = local.want_eks ? 1 : 0
  name     = "lt-${local.suffix}-eks"
  role_arn = aws_iam_role.eks[0].arn

  vpc_config {
    subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  }

  enabled_cluster_log_types = var.enable_logging ? ["api", "audit", "authenticator", "controllerManager", "scheduler"] : []

  tags       = { Name = "${local.name}-eks" }
  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}
