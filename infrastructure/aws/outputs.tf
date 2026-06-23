output "account_id" {
  description = "AWS account ID (account collector)"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  value = var.region
}

output "cloudtrail_bucket" {
  description = "CloudTrail S3 bucket (cloudtrail)"
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_trail_name" {
  value = aws_cloudtrail.org.name
}

output "vpc_id" {
  description = "Lab VPC (vpc_flow)"
  value       = aws_vpc.lab.id
}

output "vpc_flow_log_group" {
  value = aws_cloudwatch_log_group.vpc_flow.name
}

output "alb_arn" {
  description = "Application load balancer (elb_alb)"
  value       = aws_lb.lab.arn
}

output "waf_web_acl_arn" {
  description = "WAF Web ACL (waf)"
  value       = aws_wafv2_web_acl.lab.arn
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution (cloudfront)"
  value       = try(aws_cloudfront_distribution.lab[0].id, null)
}

output "app_data_bucket" {
  description = "Application bucket (s3, s3_access)"
  value       = aws_s3_bucket.app_data.id
}

output "lambda_function_name" {
  value = aws_lambda_function.lab.function_name
}

output "eks_cluster_name" {
  description = "EKS cluster (eks_audit)"
  value       = try(module.eks[0].cluster_name, null)
}

output "kms_key_arn" {
  value = aws_kms_key.lab.arn
}

output "secrets_manager_secret_arn" {
  value = aws_secretsmanager_secret.lab.arn
}

output "guardduty_detector_id" {
  value = var.use_existing_account_services ? data.aws_guardduty_detector.main[0].id : aws_guardduty_detector.lab[0].id
}

output "detective_graph_arn" {
  value = try(aws_detective_graph.lab[0].graph_arn, null)
}

output "route53_resolver_log_config" {
  value = try(aws_route53_resolver_query_log_config.lab[0].id, null)
}

output "acquire_kit_hints" {
  description = "Suggested Acquire parameters after apply"
  value = {
    cloud   = "aws"
    region  = var.region
    account = data.aws_caller_identity.current.account_id
    pack    = "baseline-ir-aws"
  }
}

output "alb_dns_name" {
  value = aws_lb.lab.dns_name
}
