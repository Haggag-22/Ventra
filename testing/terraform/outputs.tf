output "account_id" {
  value = local.account_id
}

output "region" {
  value = var.region
}

output "name_prefix" {
  value = local.name
}

output "enable_logging" {
  value = var.enable_logging
}

output "enable_expensive" {
  value = var.enable_expensive
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "log_buckets" {
  description = "Where each S3-bound log source ships."
  value = {
    archive    = aws_s3_bucket.log_archive.bucket
    cloudtrail = var.enable_logging ? aws_s3_bucket.cloudtrail[0].bucket : "(logging off)"
    alb        = aws_s3_bucket.alb_logs.bucket
    cloudfront = aws_s3_bucket.cloudfront_logs.bucket
    config     = local.do_config ? aws_s3_bucket.config[0].bucket : "(pre-existing / not managed)"
  }
}

output "inventory_buckets" {
  value = {
    app       = aws_s3_bucket.app.bucket
    misconfig = aws_s3_bucket.misconfig.bucket
    pii       = aws_s3_bucket.pii.bucket
  }
}

output "alb_dns_name" {
  description = "Hit this in a loop to generate ALB + WAF access logs."
  value       = aws_lb.main.dns_name
}

output "cloudfront_domain" {
  description = "Hit this to generate CloudFront access logs."
  value       = aws_cloudfront_distribution.main.domain_name
}

output "api_invoke_url" {
  description = "Call this to generate API Gateway access logs."
  value       = "https://${aws_api_gateway_rest_api.main.id}.execute-api.${local.region}.amazonaws.com/${aws_api_gateway_stage.main.stage_name}/ping"
}

output "instance_id" {
  value = var.create_ec2 ? aws_instance.main[0].id : "(ec2 skipped)"
}

output "snapshot_id" {
  value = var.create_ec2 ? aws_ebs_snapshot.main[0].id : "(ec2 skipped)"
}

output "lambda_function" {
  value = aws_lambda_function.main.function_name
}

output "dynamodb_table" {
  value = aws_dynamodb_table.main.name
}

output "iam_user" {
  value = aws_iam_user.main.name
}

output "tier3_endpoints" {
  description = "Populated per-service when enable_expensive or the matching enable_* toggle is on."
  value = {
    opensearch = local.want_opensearch ? aws_opensearch_domain.main[0].endpoint : "(off)"
    rds        = local.want_rds ? aws_db_instance.main[0].address : "(off)"
    eks        = local.want_eks ? aws_eks_cluster.main[0].endpoint : "(off)"
    firewall   = local.want_network_firewall ? aws_networkfirewall_firewall.main[0].arn : "(off)"
  }
}
