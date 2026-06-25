# Azure collector lab

Terraform stack for **22 Azure Ventra collectors**. Entra/M365 identity collectors use tenant-wide APIs — ensure audit logging is enabled in the tenant (see below).

## Collectors covered (Terraform)

| Collector | Resource |
|-----------|----------|
| subscription | Subscription context |
| activity_log | Diagnostic setting on subscription |
| log_analytics | Log Analytics workspace |
| diag_posture | Diagnostic settings on storage, KV, firewall, appgw |
| resource_graph | Inventory (existing RG resources) |
| defender | Defender for Cloud Standard pricing |
| vnet_flow | VNet flow logs + Traffic Analytics (NSG flow logs deprecated for new deployments) |
| azure_firewall | Azure Firewall + diagnostics (toggle) |
| app_gateway | Application Gateway v2 + diagnostics (toggle) |
| front_door | Front Door Standard + diagnostics (toggle) |
| dns | Public DNS zone + A record |
| storage_access | Storage account + blob + diagnostics |
| key_vault | Key Vault + secret + diagnostics |
| aks_audit | AKS + kube-audit diagnostics (toggle) |

## Manual tenant setup (Entra / M365)

These collectors need **Entra ID** and **Microsoft 365** audit — not fully provisioned by Terraform:

| Collector | Manual step |
|-----------|-------------|
| entra_signin | Entra sign-in logs (Premium P1+ or trial) |
| entra_audit | Entra audit logs |
| entra_directory | Directory objects |
| rbac | Role assignments in subscription |
| oauth_consent | OAuth app grants (create test app consent in tenant) |
| unified_audit | M365 Unified Audit Log enabled |
| unified_audit_search | Purview audit search API access |

Before collection: sign into Azure Portal + M365 as a test user to generate sign-in and audit events.

## Deploy

```bash
cd infrastructure/azure
cp terraform.tfvars.example terraform.tfvars
# set subscription_id and tenant_id
az login
terraform init
terraform plan
terraform apply
```

Defaults disable `enable_firewall`, `enable_aks`, and `enable_front_door` for Free Trial / Student subscriptions. Set `vm_size = "Standard_B2s"` if B-series capacity errors occur.

## Acquire

Use pack `baseline-ir-azure`. Grant the collector app/service principal `docs/iam-policies/azure-collector-readonly.json` permissions in the subscription + Graph scopes for Entra/M365.

## Logging

See `logging.tf` — VNet flow logs, subscription activity to Storage + Log Analytics (single diagnostic setting), and diagnostic settings on in-scope resources (VM, firewall, appgw, storage, KV, AKS when enabled). Public DNS zones do not support diagnostic settings.
