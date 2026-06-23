# Comprehensive logging for all Ventra AWS collectors (including log_posture sources).

resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${local.name}-alb-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_elb_service_account.main.arn }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.alb_logs.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "vpc_flow" {
  bucket        = "${local.name}-vpc-flow-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "vpc_flow" {
  bucket                  = aws_s3_bucket.vpc_flow.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "vpc_flow_bucket" {
  statement {
    sid = "AWSLogDeliveryWrite"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.vpc_flow.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
  statement {
    sid = "AWSLogDeliveryAclCheck"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.vpc_flow.arn]
  }
}

resource "aws_s3_bucket_policy" "vpc_flow" {
  bucket = aws_s3_bucket.vpc_flow.id
  policy = data.aws_iam_policy_document.vpc_flow_bucket.json
}

resource "aws_flow_log" "vpc_s3" {
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.vpc_flow.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.lab.id
  tags                 = { Name = "${local.name}-vpc-flow-s3" }

  depends_on = [aws_s3_bucket_policy.vpc_flow]
}

resource "aws_wafv2_web_acl" "regional" {
  name  = "${local.name}-waf-regional"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-waf-regional"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetRegional"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_cloudwatch_log_group" "waf_regional" {
  name              = "aws-waf-logs-${local.name}-regional"
  retention_in_days = 7
}

resource "aws_wafv2_web_acl_logging_configuration" "regional" {
  resource_arn            = aws_wafv2_web_acl.regional.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_regional.arn]
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.lab.arn
  web_acl_arn  = aws_wafv2_web_acl.regional.arn
}

resource "aws_cloudwatch_log_resource_policy" "route53_resolver" {
  count       = var.enable_route53_resolver ? 1 : 0
  policy_name = "${local.name}-route53-resolver"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "route53resolver.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.resolver[0].arn}:*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/ventra/${local.name}/apigateway"
  retention_in_days = 7
}

resource "aws_api_gateway_rest_api" "lab" {
  name = "${local.name}-api"
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.lab.id
  parent_id   = aws_api_gateway_rest_api.lab.root_resource_id
  path_part   = "hello"
}

resource "aws_api_gateway_method" "get" {
  rest_api_id   = aws_api_gateway_rest_api.lab.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id             = aws_api_gateway_rest_api.lab.id
  resource_id             = aws_api_gateway_resource.proxy.id
  http_method             = aws_api_gateway_method.get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.lab.invoke_arn
}

resource "aws_api_gateway_deployment" "lab" {
  rest_api_id = aws_api_gateway_rest_api.lab.id
  depends_on  = [aws_api_gateway_integration.lambda]
}

resource "aws_api_gateway_stage" "lab" {
  deployment_id = aws_api_gateway_deployment.lab.id
  rest_api_id   = aws_api_gateway_rest_api.lab.id
  stage_name    = "prod"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
    format = jsonencode({
      requestId   = "$context.requestId"
      ip          = "$context.identity.sourceIp"
      requestTime = "$context.requestTime"
      httpMethod  = "$context.httpMethod"
      status      = "$context.status"
    })
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lab.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.lab.execution_arn}/*/*"
}

resource "aws_db_subnet_group" "lab" {
  name       = "${local.name}-db"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "rds" {
  name   = "${local.name}-rds"
  vpc_id = aws_vpc.lab.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "lab" {
  identifier                      = "${local.name}-pg"
  engine                          = "postgres"
  engine_version                  = "16"
  instance_class                  = "db.t3.micro"
  allocated_storage               = 20
  username                        = "ventra"
  password                        = "CHANGE_ME_LAB_ONLY"
  db_subnet_group_name            = aws_db_subnet_group.lab.name
  vpc_security_group_ids          = [aws_security_group.rds.id]
  skip_final_snapshot             = true
  publicly_accessible             = false
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
}

resource "aws_dynamodb_table" "lab" {
  name         = "${local.name}-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  attribute {
    name = "pk"
    type = "S"
  }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/ventra/${local.name}/opensearch"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${local.name}-opensearch"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "es.amazonaws.com" }
      Action    = ["logs:PutLogEvents", "logs:CreateLogStream"]
      Resource  = "${aws_cloudwatch_log_group.opensearch.arn}:*"
    }]
  })
}

resource "aws_iam_service_linked_role" "opensearch" {
  aws_service_name = "opensearchservice.amazonaws.com"
  description      = "Ventra lab OpenSearch VPC access"
}

resource "aws_opensearch_domain" "lab" {
  domain_name    = "${local.name}-os"
  engine_version = "OpenSearch_2.11"
  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
  vpc_options {
    subnet_ids         = [aws_subnet.private[0].id]
    security_group_ids = [aws_security_group.web.id]
  }
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }
  depends_on = [
    aws_cloudwatch_log_resource_policy.opensearch,
    aws_iam_service_linked_role.opensearch,
  ]
}

resource "aws_networkfirewall_rule_group" "lab" {
  capacity = 100
  name     = "${local.name}-nfw-rules"
  type     = "STATELESS"
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              protocols = [6]
              source {
                address_definition = "0.0.0.0/0"
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
            }
          }
        }
      }
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "lab" {
  name = "${local.name}-nfw-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateless_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.lab.arn
    }
  }
}

resource "aws_networkfirewall_firewall" "lab" {
  name                = "${local.name}-nfw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.lab.arn
  vpc_id              = aws_vpc.lab.id
  subnet_mapping {
    subnet_id = aws_subnet.private[0].id
  }
}

resource "aws_cloudwatch_log_group" "network_firewall" {
  name              = "/ventra/${local.name}/network-firewall"
  retention_in_days = 7
}

resource "aws_networkfirewall_logging_configuration" "lab" {
  firewall_arn = aws_networkfirewall_firewall.lab.arn
  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
  }
}
