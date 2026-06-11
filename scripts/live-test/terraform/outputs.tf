output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "region" {
  value = var.region
}

output "vpc_id" {
  value = aws_vpc.test.id
}

output "instance_id" {
  value = var.create_ec2 ? aws_instance.test[0].id : "(ec2 skipped)"
}

output "snapshot_id" {
  value = var.create_ec2 ? aws_ebs_snapshot.test[0].id : "(ec2 skipped)"
}

output "buckets" {
  value = {
    logs      = aws_s3_bucket.logs.bucket
    misconfig = aws_s3_bucket.misconfig.bucket
    pii       = aws_s3_bucket.pii.bucket
  }
}

output "pii_bucket" {
  description = "Bucket the Macie classification job scans."
  value       = aws_s3_bucket.pii.bucket
}

output "kms_key_id" {
  value = aws_kms_key.test.key_id
}

output "iam_user" {
  value = aws_iam_user.test.name
}

output "lambda_function" {
  value = aws_lambda_function.test.function_name
}
