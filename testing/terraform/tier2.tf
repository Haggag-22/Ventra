# ===========================================================================
# TIER 2 — detection services + more log wiring. Detection services are
# account/region singletons; existence is gated by var.enable_logging so the
# OFF run produces "service_not_enabled" gaps.
#
# These are account/region SINGLETONS. Whether Terraform manages each one is
# decided AUTOMATICALLY in detect.tf — services already enabled in the account
# are left alone (no "already exists" failures, no manual flags).
# ===========================================================================

# --- GuardDuty --------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  count  = local.do_guardduty ? 1 : 0
  enable = true
  tags   = { Name = "${local.name}-guardduty" }
}

# --- Security Hub -----------------------------------------------------------
resource "aws_securityhub_account" "main" {
  count = local.do_securityhub ? 1 : 0
}

# --- Detective --------------------------------------------------------------
resource "aws_detective_graph" "main" {
  count = local.do_detective ? 1 : 0
  tags  = { Name = "${local.name}-detective" }
}

# --- Inspector2 -------------------------------------------------------------
resource "aws_inspector2_enabler" "main" {
  count          = local.do_inspector2 ? 1 : 0
  account_ids    = [local.account_id]
  resource_types = ["EC2", "ECR"]
}

# --- Macie2 -----------------------------------------------------------------
resource "aws_macie2_account" "main" {
  count = local.do_macie ? 1 : 0
}

# ---------------------------------------------------------------------------
# WAF (regional, associated with the ALB). ON = logging config -> CW log group;
# OFF = web ACL with logging disabled.
# ---------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "main" {
  name        = "${local.name}-web-acl"
  description = "Ventra logging-test regional web ACL"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ventraLoggingTest"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${local.name}-web-acl" }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# WAF CloudWatch logging requires a log group whose name starts with "aws-waf-logs-".
resource "aws_cloudwatch_log_group" "waf" {
  count             = var.enable_logging ? 1 : 0
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = 1
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = var.enable_logging ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]
}

# ---------------------------------------------------------------------------
# Route53 Resolver query logs -> S3. ON = config + VPC association; OFF = none.
# ---------------------------------------------------------------------------
resource "aws_route53_resolver_query_log_config" "main" {
  count           = var.enable_logging ? 1 : 0
  name            = "${local.name}-resolver-logs"
  destination_arn = aws_s3_bucket.log_archive.arn
  depends_on      = [aws_s3_bucket_policy.log_archive]
}

resource "aws_route53_resolver_query_log_config_association" "main" {
  count                        = var.enable_logging ? 1 : 0
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.main[0].id
  resource_id                  = aws_vpc.main.id
}

# ---------------------------------------------------------------------------
# API Gateway (REST) with a MOCK endpoint. ON = stage access logging -> CW;
# OFF = stage with access logging disabled.
# ---------------------------------------------------------------------------
resource "aws_api_gateway_rest_api" "main" {
  name        = "${local.name}-api"
  description = "Ventra logging-test API"
}

resource "aws_api_gateway_resource" "ping" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "ping"
}

resource "aws_api_gateway_method" "ping_get" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.ping.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "ping" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.ping.id
  http_method = aws_api_gateway_method.ping_get.http_method
  type        = "MOCK"
  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "ping_200" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.ping.id
  http_method = aws_api_gateway_method.ping_get.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "ping_200" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.ping.id
  http_method = aws_api_gateway_method.ping_get.http_method
  status_code = aws_api_gateway_method_response.ping_200.status_code
  depends_on  = [aws_api_gateway_integration.ping]
}

resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  depends_on  = [aws_api_gateway_integration.ping]

  triggers = {
    redeploy = sha1(jsonencode([
      aws_api_gateway_resource.ping.id,
      aws_api_gateway_method.ping_get.id,
      aws_api_gateway_integration.ping.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "apigw" {
  count             = var.enable_logging ? 1 : 0
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = 1
}

# API Gateway requires an account-level CloudWatch Logs role before any stage can
# emit access logs. This is a per-region account setting (singleton).
resource "aws_iam_role" "apigw_cloudwatch" {
  count = var.enable_logging ? 1 : 0
  name  = "${local.name}-apigw-cw-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "apigateway.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "apigw_cloudwatch" {
  count      = var.enable_logging ? 1 : 0
  role       = aws_iam_role.apigw_cloudwatch[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "main" {
  count               = var.enable_logging ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.apigw_cloudwatch[0].arn
  depends_on          = [aws_iam_role_policy_attachment.apigw_cloudwatch]
}

resource "aws_api_gateway_stage" "main" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  deployment_id = aws_api_gateway_deployment.main.id
  stage_name    = "test"
  depends_on    = [aws_api_gateway_account.main]

  dynamic "access_log_settings" {
    for_each = var.enable_logging ? [1] : []
    content {
      destination_arn = aws_cloudwatch_log_group.apigw[0].arn
      format = jsonencode({
        requestId      = "$context.requestId"
        ip             = "$context.identity.sourceIp"
        httpMethod     = "$context.httpMethod"
        resourcePath   = "$context.resourcePath"
        status         = "$context.status"
        responseLength = "$context.responseLength"
      })
    }
  }
}
