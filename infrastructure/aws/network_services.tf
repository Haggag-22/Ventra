# Targets: elb_alb, waf, cloudfront, route53_resolver

resource "aws_lb" "lab" {
  name               = "${local.name}-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  tags               = { Name = "${local.name}-alb" }

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
    prefix  = "alb"
  }

  depends_on = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "ALB ingress"
  vpc_id      = aws_vpc.lab.id
  ingress {
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
}

resource "aws_lb_target_group" "web" {
  name     = "${local.name}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.lab.id
  health_check { path = "/" }
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.lab.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_cloudwatch_log_group" "alb" {
  name              = "/ventra/${local.name}/alb"
  retention_in_days = 7
}

resource "aws_wafv2_web_acl" "lab" {
  provider    = aws.us_east_1
  name        = "${local.name}-waf"
  description = "Ventra lab WAF"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-waf"
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
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "lab" {
  provider                = aws.us_east_1
  resource_arn            = aws_wafv2_web_acl.lab.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

resource "aws_cloudwatch_log_group" "waf" {
  provider          = aws.us_east_1
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = 7
}

resource "aws_s3_bucket" "cloudfront_logs" {
  count         = var.enable_cloudfront ? 1 : 0
  bucket        = "${local.name}-cf-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "cloudfront_logs" {
  count  = var.enable_cloudfront ? 1 : 0
  bucket = aws_s3_bucket.cloudfront_logs[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudfront_logs" {
  count  = var.enable_cloudfront ? 1 : 0
  bucket = aws_s3_bucket.cloudfront_logs[0].id

  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "cloudfront_logs" {
  count  = var.enable_cloudfront ? 1 : 0
  bucket = aws_s3_bucket.cloudfront_logs[0].id
  acl    = "log-delivery-write"

  depends_on = [
    aws_s3_bucket_ownership_controls.cloudfront_logs,
    aws_s3_bucket_public_access_block.cloudfront_logs,
  ]
}

data "aws_iam_policy_document" "cloudfront_logs" {
  count = var.enable_cloudfront ? 1 : 0

  statement {
    sid = "AllowCloudFrontLogDelivery"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudfront_logs[0].arn}/*"]
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
      values   = ["arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/*"]
    }
  }

  statement {
    sid = "AllowCloudFrontLogDeliveryAclCheck"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudfront_logs[0].arn]
  }
}

resource "aws_s3_bucket_policy" "cloudfront_logs" {
  count  = var.enable_cloudfront ? 1 : 0
  bucket = aws_s3_bucket.cloudfront_logs[0].id
  policy = data.aws_iam_policy_document.cloudfront_logs[0].json
}

resource "aws_cloudfront_origin_access_control" "lab" {
  count                             = var.enable_cloudfront ? 1 : 0
  name                              = "${local.name}-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_s3_bucket" "static_site" {
  count         = var.enable_cloudfront ? 1 : 0
  bucket        = "${local.name}-static-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_object" "static_index" {
  count   = var.enable_cloudfront ? 1 : 0
  bucket  = aws_s3_bucket.static_site[0].id
  key     = "index.html"
  content = "<html><body>ventra lab</body></html>"
}

resource "aws_cloudfront_distribution" "lab" {
  count    = var.enable_cloudfront ? 1 : 0
  provider = aws.us_east_1
  enabled  = true
  comment  = "Ventra collector lab"

  origin {
    domain_name              = aws_s3_bucket.static_site[0].bucket_regional_domain_name
    origin_id                = "s3-static"
    origin_access_control_id = aws_cloudfront_origin_access_control.lab[0].id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-static"
    viewer_protocol_policy = "redirect-to-https"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.cloudfront_logs[0].bucket_domain_name
    prefix          = "cloudfront/"
  }

  web_acl_id = aws_wafv2_web_acl.lab.arn

  depends_on = [
    aws_s3_bucket_acl.cloudfront_logs,
    aws_s3_bucket_policy.cloudfront_logs,
  ]
}

resource "aws_route53_resolver_query_log_config" "lab" {
  count           = var.enable_route53_resolver ? 1 : 0
  name            = "${local.name}-resolver-logs"
  destination_arn = aws_cloudwatch_log_group.resolver[0].arn
}

resource "aws_route53_resolver_query_log_config_association" "lab" {
  count                        = var.enable_route53_resolver ? 1 : 0
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.lab[0].id
  resource_id                  = aws_vpc.lab.id
}

resource "aws_cloudwatch_log_group" "resolver" {
  count             = var.enable_route53_resolver ? 1 : 0
  name              = "/ventra/${local.name}/route53-resolver"
  retention_in_days = 7
}
