# AWS collector lab

Live AWS environment for exercising **every Ventra AWS collector** (all 25) with one coherent attack story (same narrative as `tests/fixtures/generate_demo_case.py`).

## Collector coverage matrix

Every collector in `collector/engine/registry/aws.py` has matching infrastructure **and** seed activity.

| Collector | Lab infrastructure | Seed activity |
|-----------|-------------------|---------------|
| `account` | Terraform + STS caller | IAM/S3 API calls as dbadmin |
| `cloudtrail` | Multi-region trail + S3 data events on sensitive bucket | All seed API calls logged |
| `iam` | Compromised dbadmin user + app EC2 role + Lambda role | Backdoor user created |
| `vpc_flow` | VPC flow logs → CloudWatch | All lab network traffic |
| `waf` | WAFv2 on ALB + S3 logging (`aws-waf-logs-*`) + sampled requests | SQLi/XSS probes |
| `guardduty` | GuardDuty detector enabled | Sample findings injected |
| `macie` | Macie enabled (`enable_macie`) | Seed starts one-time classification job on sensitive bucket |
| `detective` | Detective graph (`enable_detective`) | Uses GuardDuty relationship data |
| `config` | Config recorder + delivery channel (`enable_config`) | Records all lab resource changes |
| `securityhub` | Security Hub + FSBP standard (`enable_securityhub`) | Aggregates GuardDuty sample findings |
| `inspector2` | Inspector2 enabled for EC2/ECR/Lambda | Async vulnerability scans |
| `kms` | CMK with rotation | Seed describe + encrypt on lab CMK |
| `secrets` | Secrets Manager db creds | Seed reads secret metadata + value |
| `ec2` | Web EC2 + EBS snapshot + instance profile | Discovery + SSM commands from instance |
| `s3` | Sensitive data bucket + policies | List + marker object read |
| `lambda` | Python Lambda function | Five direct invokes |
| `lambda_logs` | CloudWatch log group | Invoke burst writes CloudWatch lines |
| `elb_alb` | ALB with access logs → S3 | HTTP/SQLi/XSS probes → S3 access logs |
| `apigateway` | REST API + stage access logs → CloudWatch | GET /admin probes |
| `cloudfront` | Distribution + **standard logging → S3** | HTTPS probes via CloudFront domain |
| `s3_access` | Server access logging on sensitive bucket | Reads generate access log entries |
| `route53_resolver` | Resolver query logs on VPC → CloudWatch | SSM `dig`/`nslookup` burst from EC2 |
| `eks_audit` | EKS cluster with audit logging (`enable_eks`) | Kubernetes API list calls → audit logs |
| `rds` | RDS Postgres + CW log exports | SSM port probe from EC2 → postgresql logs |
| `log_posture` | OpenSearch + DynamoDB streams + Network Firewall (`enable_log_posture`) | DynamoDB put/update; posture sources provisioned |

## Deploy

Prerequisites: AWS CLI credentials with admin access, Terraform >= 1.5.

```bash
cd docs/deployment/aws/collector-lab/terraform
cp terraform.tfvars.example terraform.tfvars   # optional cost toggles
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Or from repo root:

```bash
make aws-lab-deploy
```

**Cost warning:** NAT gateway, RDS, EKS, OpenSearch, Network Firewall, and Detective incur ongoing charges. See `terraform.tfvars.example` for toggles.

**Config note:** AWS allows one Config recorder per region. If your account already has one, set `enable_config = false` in `terraform.tfvars`. The `config` collector still reads the existing recorder.

## Seed the attack story

After apply, run the seed script to generate API activity, GuardDuty samples, Lambda logs, DynamoDB writes, DNS queries, and HTTP probes:

```bash
make aws-lab-seed
```

Some log destinations (CloudFront S3, WAF S3, ALB S3) can take **15–60 minutes** before first objects appear. Re-run collection after waiting if those collectors return empty.

## Collect with Ventra

1. Deploy collector IAM (`docs/deployment/aws/terraform`) if not already done.
2. Add the `ventra-collector` credentials in **Configuration → Providers**.
3. Run collection against this account with all AWS artifacts or pack `baseline-ir-aws`.
4. Use case id `CASE-LAB-AWS` (terraform default).

Verify coverage:

```bash
cd docs/deployment/aws/collector-lab/terraform
terraform output collector_coverage
terraform output collectors_covered
```

## Tear down

```bash
cd docs/deployment/aws/collector-lab/terraform
terraform destroy
```

Or: `make aws-lab-destroy`
