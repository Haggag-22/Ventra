resource "aws_guardduty_detector" "lab" {
  enable = true
  tags   = merge(local.common_tags, { Collector = "guardduty" })
}

resource "aws_inspector2_enabler" "lab" {
  account_ids    = [local.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]

  timeouts {
    create = "20m"
    delete = "20m"
  }
}

resource "aws_macie2_account" "lab" {
  count = var.enable_macie ? 1 : 0

  lifecycle {
    # Macie may already be enabled in the account from a prior lab run.
    ignore_changes = all
  }
}

resource "aws_securityhub_account" "lab" {
  count = var.enable_securityhub ? 1 : 0

  lifecycle {
    # Security Hub may already be subscribed in the account.
    ignore_changes = all
  }
}

resource "aws_securityhub_standards_subscription" "foundational" {
  count         = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.lab]
}

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

  tags = merge(local.common_tags, { Collector = "waf" })
}

resource "aws_wafv2_web_acl_logging_configuration" "lab" {
  resource_arn            = aws_wafv2_web_acl.lab.arn
  log_destination_configs = [aws_s3_bucket.waf_logs.arn]

  depends_on = [aws_s3_bucket_policy.waf_logs]
}

# WAF collector also uses GetSampledRequests when full S3 logging is slow to appear.

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.lab.arn
  web_acl_arn  = aws_wafv2_web_acl.lab.arn
}
