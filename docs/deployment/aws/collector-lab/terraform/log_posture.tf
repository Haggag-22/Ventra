# Resources for the log_posture collector (OpenSearch, DynamoDB Streams, Network Firewall).
# These are posture-only sources — Ventra records whether logging is on, not the log bodies.

resource "aws_cloudwatch_log_group" "opensearch" {
  count             = var.enable_log_posture ? 1 : 0
  name              = "/${var.project}/opensearch"
  retention_in_days = 14
  tags              = { Collector = "log_posture", Source = "opensearch" }
}

data "aws_iam_policy_document" "opensearch_logs" {
  count = var.enable_log_posture ? 1 : 0
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
    actions   = ["logs:PutLogEvents", "logs:CreateLogStream"]
    resources = ["${aws_cloudwatch_log_group.opensearch[0].arn}:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  count           = var.enable_log_posture ? 1 : 0
  policy_name     = "${var.project}-opensearch-logs"
  policy_document = data.aws_iam_policy_document.opensearch_logs[0].json
}

resource "aws_opensearch_domain" "lab" {
  count       = var.enable_log_posture ? 1 : 0
  domain_name = "${var.project}-search"
  tags        = { Collector = "log_posture", Source = "opensearch" }

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = true
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch[0].arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true
  }

  depends_on = [aws_cloudwatch_log_resource_policy.opensearch]
}

resource "aws_dynamodb_table" "lab" {
  count        = var.enable_log_posture ? 1 : 0
  name         = "${var.project}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
  tags         = { Collector = "log_posture", Source = "dynamodb_streams" }

  attribute {
    name = "session_id"
    type = "S"
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
}

resource "aws_subnet" "firewall" {
  for_each = var.enable_log_posture ? toset(local.azs) : toset([])

  vpc_id            = aws_vpc.lab.id
  cidr_block        = cidrsubnet(aws_vpc.lab.cidr_block, 4, index(local.azs, each.key) + 12)
  availability_zone = each.key
  tags              = { Name = "${var.project}-firewall-${each.key}", Collector = "log_posture" }
}

resource "aws_networkfirewall_rule_group" "lab" {
  count    = var.enable_log_posture ? 1 : 0
  name     = "${var.project}-allow-http"
  type     = "STATELESS"
  capacity = 100
  tags     = { Collector = "log_posture" }

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
              protocols = [6]
              destination_port {
                from_port = 80
                to_port   = 80
              }
            }
          }
        }
      }
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "lab" {
  count = var.enable_log_posture ? 1 : 0
  name  = "${var.project}-fw-policy"
  tags  = { Collector = "log_posture" }

  firewall_policy {
    stateless_default_actions          = ["aws:pass"]
    stateless_fragment_default_actions = ["aws:pass"]
    stateless_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.lab[0].arn
    }
  }
}

resource "aws_networkfirewall_firewall" "lab" {
  count               = var.enable_log_posture ? 1 : 0
  name                = "${var.project}-fw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.lab[0].arn
  vpc_id              = aws_vpc.lab.id
  tags                = { Collector = "log_posture", Source = "network_firewall" }

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall
    content {
      subnet_id = subnet_mapping.value.id
    }
  }
}

resource "aws_cloudwatch_log_group" "network_firewall" {
  count             = var.enable_log_posture ? 1 : 0
  name              = "/${var.project}/network-firewall"
  retention_in_days = 14
  tags              = { Collector = "log_posture", Source = "network_firewall" }
}

resource "aws_networkfirewall_logging_configuration" "lab" {
  count         = var.enable_log_posture ? 1 : 0
  firewall_arn  = aws_networkfirewall_firewall.lab[0].arn
  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall[0].name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}
