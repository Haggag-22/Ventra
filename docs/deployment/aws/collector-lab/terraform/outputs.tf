output "region" {
  value = var.region
}

output "case_id" {
  value = var.case_id
}

output "account_id" {
  value = local.account_id
}

output "vpc_id" {
  value = aws_vpc.lab.id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.lab.name
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail.id
}

output "alb_dns_name" {
  value = aws_lb.lab.dns_name
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.lab.domain_name
}

output "sensitive_bucket" {
  value = aws_s3_bucket.sensitive.id
}

output "access_logs_bucket" {
  value = aws_s3_bucket.access_logs.id
}

output "alb_logs_bucket" {
  value = aws_s3_bucket.alb_logs.id
}

output "waf_logs_bucket" {
  value = aws_s3_bucket.waf_logs.id
}

output "victim_user" {
  value = aws_iam_user.dbadmin.name
}

output "victim_access_key_id" {
  value     = aws_iam_access_key.dbadmin.id
  sensitive = true
}

output "victim_secret_access_key" {
  value     = aws_iam_access_key.dbadmin.secret
  sensitive = true
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.lab.id
}

output "api_gateway_invoke_url" {
  value = "${aws_api_gateway_stage.prod.invoke_url}admin"
}

output "lambda_function_name" {
  value = aws_lambda_function.processor.function_name
}

output "rds_endpoint" {
  value = aws_db_instance.lab.address
}

output "eks_cluster_name" {
  value = var.enable_eks ? aws_eks_cluster.lab[0].name : null
}

output "ec2_instance_id" {
  value = aws_instance.web.id
}

output "ebs_snapshot_id" {
  value = aws_ebs_snapshot.lab.id
}

output "collectors_covered" {
  value = [
    "account", "cloudtrail", "iam", "vpc_flow", "waf", "guardduty",
    "inspector2", "secrets", "kms", "cloudfront", "macie", "eks_audit",
    "rds", "lambda_logs", "route53_resolver", "ec2", "s3", "config",
    "elb_alb", "log_posture", "apigateway", "lambda", "detective",
    "securityhub", "s3_access",
  ]
}
