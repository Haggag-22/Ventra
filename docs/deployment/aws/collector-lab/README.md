# AWS collector lab

Live AWS environment for exercising **every Ventra AWS collector** with one coherent attack story (same narrative as `tests/fixtures/generate_demo_case.py`).

## What gets deployed

| Area | Resources | Collectors |
|------|-----------|------------|
| Logging | CloudTrail, VPC flow logs, Route53 resolver query logs, Config | `cloudtrail`, `vpc_flow`, `route53_resolver`, `config`, `log_posture` |
| Network / edge | VPC, ALB (access logs), WAF (sampled logs), CloudFront | `elb_alb`, `waf`, `cloudfront` |
| Data | S3 sensitive + access-log buckets | `s3`, `s3_access` |
| Compute | EC2 web instance, EBS snapshot | `ec2` |
| Identity | Compromised `ventra-lab-dbadmin` user + app role | `iam`, `account` |
| Security services | GuardDuty, Security Hub, Inspector2, Macie, Detective | `guardduty`, `securityhub`, `inspector2`, `macie`, `detective` |
| Serverless | Lambda + API Gateway (access logs) | `lambda`, `lambda_logs`, `apigateway` |
| Data plane | RDS Postgres, optional EKS, KMS, Secrets Manager | `rds`, `eks_audit`, `kms`, `secrets` |

## Deploy

Prerequisites: AWS CLI credentials with admin access, Terraform >= 1.5.

```bash
cd docs/deployment/aws/collector-lab/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Or from repo root:

```bash
make aws-lab-deploy
```

**Cost warning:** NAT gateway, RDS, EKS, and Detective incur ongoing charges. Set `enable_eks = false` or `enable_detective = false` in `terraform.tfvars` to reduce cost.

## Seed the attack story

After apply, run the seed script to generate API activity, S3 reads, GuardDuty sample findings, and WAF/ALB HTTP probes:

```bash
make aws-lab-seed
```

## Collect with Ventra

1. Deploy collector IAM (`docs/deployment/aws/terraform`) if not already done.
2. Add the `ventra-collector` credentials in **Configuration → Providers**.
3. Run collection against this account with all AWS artifacts (or `--pack baseline-ir-aws` plus extended artifacts).
4. Use case id `CASE-LAB-AWS` (terraform default) to tie the run to the lab tags.

## Tear down

```bash
cd docs/deployment/aws/collector-lab/terraform
terraform destroy
```
