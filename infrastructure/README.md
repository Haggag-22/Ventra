# Ventra collector test infrastructure

Terraform stacks that provision cloud resources and logging so you can run **every Ventra collector** against live accounts.

```
infrastructure/
├── README.md
├── COLLECTORS.md
├── aws/          # 22 collectors
├── azure/        # 22 collectors (+ Entra/M365 manual steps)
└── gcp/          # 16 collectors (+ Workspace manual)
```

## Before you deploy

1. Use a **dedicated test account/subscription/project**.
2. Copy `terraform.tfvars.example` → `terraform.tfvars` in each cloud folder.
3. Fill in IDs when ready.
4. `terraform init` → `terraform plan` → review cost → `terraform apply`.

Use `enable_*` toggles to reduce cost during smoke tests.

## Test flow

1. Generate activity (HTTP, storage, portal sign-ins, IAM changes).
2. Wait 15–60 minutes for logs.
3. Acquire kit → collect → import EPF → check coverage.

## IAM

`docs/iam-policies/{aws,azure,gcp}-collector-readonly.json`

## Logging coverage

Each stack includes a `logging.tf` (AWS/Azure/GCP) that turns on every log path Ventra collectors read:

| Cloud | Enabled logging |
|-------|-----------------|
| **AWS** | CloudTrail (mgmt + data + network + insights) → S3/CW; VPC flow → CW **and** S3; ALB access logs → S3; WAF regional + CloudFront → CW; Route53 resolver query logs; API Gateway access logs; RDS CW exports; DynamoDB streams; OpenSearch log publishing; Network Firewall FLOW+ALERT; S3 access logging on trail/config buckets |
| **Azure** | Subscription activity → LA + Storage; VNet **and** NSG flow logs → Storage + Traffic Analytics; diagnostics on firewall, appgw, front door, DNS, storage, KV, AKS, VM, NIC |
| **GCP** | Audit configs (admin/system/data); log sinks → GCS; VPC flow + firewall + LB + VM + CF; 30-day `_Default` retention; Ops Agent on GCE for `vm_logs` |

Entra/M365 (Azure) and Workspace audit (GCP) still require tenant admin steps — see each cloud README.

## Generate traffic after deploy

```bash
./infrastructure/scripts/generate-all.sh
# or per cloud:
./infrastructure/scripts/aws/generate.sh -n 5
```

See `infrastructure/scripts/README.md` for details.
