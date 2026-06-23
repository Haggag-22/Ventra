# AWS collector lab

Terraform stack targeting all **22 AWS Ventra collectors**.

## Collectors covered

| Collector | Resource |
|-----------|----------|
| account | Current account (data source) |
| cloudtrail | Multi-region trail → S3 + CloudWatch |
| iam | Lab IAM user + roles |
| vpc_flow | VPC flow logs → CloudWatch |
| waf | WAFv2 Web ACL + logging |
| guardduty | Detector enabled |
| securityhub | Account enabled |
| config | Recorder + S3 delivery |
| detective | Graph (toggle) |
| macie | Account enabled (toggle) |
| inspector2 | Enabler (toggle) |
| route53_resolver | Query log config on VPC |
| cloudfront | Distribution + S3 origin (toggle) |
| elb_alb | Application Load Balancer |
| lambda | Node.js function |
| s3 / s3_access | App data + access log buckets |
| ec2 | Web instance behind ALB |
| secrets | Secrets Manager secret |
| kms | CMK + alias |
| eks_audit | EKS cluster audit logs (toggle) |
| log_posture | CloudTrail + S3 access logging posture |

## Deploy

```bash
cd infrastructure/aws
cp terraform.tfvars.example terraform.tfvars
# edit region / toggles
terraform init
terraform plan
terraform apply
```

Use a dedicated test account. Review `enable_*` toggles before apply — full stack can exceed **$150/mo** (EKS + NAT + Detective).

## After apply

1. Generate traffic: `curl http://$(terraform output -raw alb_dns_name)` (add output if needed), upload S3 objects, invoke Lambda.
2. Wait 15–60 minutes for logs.
3. Acquire kit with pack `baseline-ir-aws` (or full artifact list).
4. Run collector role from `docs/iam-policies/aws-collector-readonly.json`.

## Outputs

`terraform output acquire_kit_hints` gives region + account for the Acquire UI.

## Logging

See `logging.tf` — all collector log paths enabled including dual VPC flow delivery (CloudWatch + S3), ALB access logs, regional WAF logging, CloudTrail insights/network/data events, and log_posture sources (API Gateway, RDS, DynamoDB streams, OpenSearch, Network Firewall).
