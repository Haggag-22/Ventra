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

output "cloudfront_logs_bucket" {
  value = aws_s3_bucket.cloudfront_logs.id
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

output "dynamodb_table_name" {
  value = var.enable_log_posture ? aws_dynamodb_table.lab[0].name : null
}

output "opensearch_domain" {
  value = var.enable_log_posture ? aws_opensearch_domain.lab[0].domain_name : null
}

output "network_firewall_arn" {
  value = var.enable_log_posture ? aws_networkfirewall_firewall.lab[0].arn : null
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
  value = try("${aws_api_gateway_stage.prod.invoke_url}/admin", null)
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

# Per-collector coverage: what the lab provisions vs what the seed script generates activity for.
output "collector_coverage" {
  value = {
    account            = { infra = true, activity = "terraform + seed IAM calls" }
    cloudtrail         = { infra = true, activity = "seed IAM/S3 API calls + S3 data events" }
    iam                = { infra = true, activity = "seed creates backdoor user" }
    vpc_flow           = { infra = true, activity = "all lab traffic" }
    waf                = { infra = true, activity = "seed SQLi/XSS probes (S3 logs + sampled requests)" }
    guardduty          = { infra = true, activity = "seed sample findings" }
    macie              = { infra = var.enable_macie, activity = "seed starts Macie classification job on sensitive bucket" }
    detective          = { infra = var.enable_detective, activity = "GuardDuty graph (no extra seed)" }
    config             = { infra = var.enable_config, activity = "recorder captures all lab changes" }
    securityhub        = { infra = var.enable_securityhub, activity = "aggregates GuardDuty sample findings" }
    inspector2         = { infra = true, activity = "scans EC2/Lambda (async)" }
    kms                = { infra = true, activity = "seed describe + encrypt on lab CMK" }
    secrets            = { infra = true, activity = "seed reads db creds secret" }
    ec2                = { infra = true, activity = "discovery + SSM commands from web instance" }
    s3                 = { infra = true, activity = "sensitive bucket list + marker read" }
    lambda             = { infra = true, activity = "seed invokes function (burst)" }
    lambda_logs        = { infra = true, activity = "invoke burst writes CloudWatch logs" }
    elb_alb            = { infra = true, activity = "seed HTTP/SQLi/XSS probes → S3 access logs" }
    apigateway         = { infra = true, activity = "seed hits /admin → CW access logs" }
    cloudfront         = { infra = true, activity = "seed HTTPS probes → S3 access logs" }
    s3_access          = { infra = true, activity = "sensitive bucket reads → server access logs" }
    route53_resolver   = { infra = true, activity = "seed SSM dig burst from EC2" }
    eks_audit          = { infra = var.enable_eks, activity = "seed Kubernetes API list calls → audit logs" }
    rds                = { infra = true, activity = "SSM port probe from EC2 → postgresql CW logs" }
    log_posture        = { infra = var.enable_log_posture, activity = "DynamoDB put/update; OpenSearch + NFW logging on" }
  }
}

output "collectors_covered" {
  value = [
    "account", "cloudtrail", "iam", "vpc_flow", "waf", "guardduty", "macie",
    "detective", "config", "securityhub", "inspector2", "kms", "secrets", "ec2",
    "s3", "lambda", "lambda_logs", "elb_alb", "apigateway", "cloudfront",
    "s3_access", "route53_resolver", "eks_audit", "rds", "log_posture",
  ]
}
