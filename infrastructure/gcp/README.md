# GCP collector lab

Terraform stack for **16 GCP Ventra collectors**.

## Collectors covered

| Collector | Resource |
|-----------|----------|
| project | Project + enabled APIs |
| iam_policy | Lab service account + IAM binding |
| cloud_audit_admin/system/data | Project audit configs + log sink |
| login_events | Admin audit + generate sign-in via Console |
| vpc_flow | Subnet flow logs |
| firewall_logs | Firewall rules with logging |
| load_balancer | External HTTP LB + access logs |
| storage_access | GCS bucket + access logging |
| cloud_functions | Cloud Functions Gen2 |
| api_gateway | API Gateway + OpenAPI backend (toggle) |
| cloud_monitoring | Alert policy + notification channel |
| vm_logs | GCE instance + nginx |
| scc_findings | Org SCC notification (toggle, needs org_id) |

## Deploy

```bash
cd infrastructure/gcp
cp terraform.tfvars.example terraform.tfvars
terraform init && terraform plan && terraform apply
```

## Acquire

Pack `baseline-ir-gcp`. IAM: `docs/iam-policies/gcp-collector-readonly.json`.

## Logging

See `logging.tf` — audit log sinks, per-service logging sinks to GCS, extended retention, and Google Ops Agent on the lab VM for `vm_logs`.
