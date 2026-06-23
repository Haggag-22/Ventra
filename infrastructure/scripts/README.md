# Ventra lab traffic generators

Scripts that exercise the Terraform lab infrastructure and produce logs for collector testing.

Run **after** `terraform apply` in each cloud folder. Authenticate first:

```bash
# AWS
aws sso login   # or export AWS_PROFILE

# Azure
az login

# GCP
gcloud auth application-default login
gcloud config set project YOUR-PROJECT-ID
```

## Quick start

```bash
# One cloud
./infrastructure/scripts/aws/generate.sh

# All clouds
./infrastructure/scripts/generate-all.sh

# More iterations, preview only
./infrastructure/scripts/aws/generate.sh -n 10 --dry-run
```



## Options (all scripts)

| Flag | Description |
|------|-------------|
| `-n, --iterations N` | Repeat each traffic pattern N times (default: 3) |
| `-d, --dry-run` | Print actions without executing |
| `-p, --pause SECS` | Pause between iterations (default: 1) |

Environment: `ITERATIONS`, `DRY_RUN`, `PAUSE_SECS`

## What each script generates

### AWS (`aws/generate.sh`)

Single script: benign traffic **and** 15 lab-native MITRE techniques (no Stratus). Reads Terraform outputs from `infrastructure/aws/`.

| Target | Activity |
|--------|----------|
| ALB, CloudFront | HTTP GET requests → access logs, WAF samples |
| S3 app bucket | List, PutObject, GetObject → data events + access logs |
| Lambda + API Gateway | Invoke + HTTP → function logs + API access logs |
| KMS, Secrets Manager | Encrypt + metadata read → audit events |
| DynamoDB | PutItem → streams posture |
| IAM, EC2, CloudTrail, GuardDuty | Read APIs → management events |
| EKS (if enabled) | kubectl get pods → audit logs |
| Route53 Resolver | in-VPC DNS via EKS busybox pods → query logs in CloudWatch |
| MITRE techniques | CloudTrail events on existing lab resources (IAM, S3 policy, Lambda, etc.) |

### Azure (`azure/generate.sh`)

| Target | Activity |
|--------|----------|
| App Gateway, VM, Front Door | HTTP traffic → diagnostics + flow logs |
| Storage account | Blob upload/download → storage logs |
| Key Vault | Secret read → audit logs |
| DNS zone | Record show + dig |
| Activity log, RBAC, resources | Azure control-plane reads |
| AKS (if enabled) | kubectl → kube-audit |

**Manual:** Sign into Azure Portal and M365 for Entra sign-in / Unified Audit Log.

### GCP (`gcp/generate.sh`)

| Target | Activity |
|--------|----------|
| HTTP load balancer | curl → LB + firewall + VPC flow logs |
| GCS app bucket | Upload/download → data access audit |
| Cloud Functions | HTTP + call → function logs |
| API Gateway | GET /hello |
| IAM, Compute, Logging | Read APIs → admin audit |
| GCE VM | syslog via SSH → vm_logs (needs SSH access) |

**Manual:** Google Workspace audit requires Workspace admin setup.

## Environment overrides

```bash
AWS_PROFILE=lab AWS_DIR=/path/to/aws ./aws/generate.sh
AZ_SUBSCRIPTION_ID=... AZURE_LOCATION=eastus ./azure/generate.sh
GCP_PROJECT_ID=... ./gcp/generate.sh
```

## After running

1. Wait **15–60 minutes** for logs to land in S3 / Storage / Cloud Logging / Log Analytics.
2. Build Acquire kit from Ventra GUI.
3. Run collection → import EPF → verify Logs Coverage.
