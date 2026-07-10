resource "aws_guardduty_detector" "lab" {
  enable = true
  tags   = { Collector = "guardduty" }
}

resource "aws_inspector2_enabler" "lab" {
  account_ids    = [local.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]

  timeouts {
    create = "20m"
    delete = "20m"
  }
}

# Security Hub and Macie are enabled at the account level in many orgs already.
# Collectors read existing account state — no lab-specific enablement required.

resource "aws_detective_graph" "lab" {
  count      = var.enable_detective ? 1 : 0
  depends_on = [aws_guardduty_detector.lab]
}

resource "aws_wafv2_web_acl" "lab" {
  name  = "${var.project}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockSQLi"
    priority = 1
    action {
      block {}
    }
    statement {
      sqli_match_statement {
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 1
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "BlockXSS"
    priority = 2
    action {
      block {}
    }
    statement {
      xss_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-xss"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-waf"
    sampled_requests_enabled   = true
  }

  tags = { Collector = "waf" }
}

# WAF collector uses GetSampledRequests (visibility_config.sampled_requests_enabled).
# Full WAF logging to S3 requires aws-waf-logs-* bucket naming; omitted here.

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.lab.arn
  web_acl_arn  = aws_wafv2_web_acl.lab.arn
}
