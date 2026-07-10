# Ventra deployment templates

Infrastructure as code templates for creating read-only collector principals. These mirror the policies in `docs/iam-policies/`.

| Provider | Template | Path |
|----------|----------|------|
| AWS | CloudFormation | `aws/cloudformation/ventra-collector-iam.yaml` |
| AWS | Terraform | `aws/terraform/main.tf` |
| AWS | Collector lab (live test env) | `aws/collector-lab/terraform/` |
| GCP | Terraform | `gcp/terraform/main.tf` |
| Azure | Terraform | `azure/terraform/main.tf` |

Static copies are served from the Ventra console at `/docs/deployment/...` for download during Authentication setup.

## Usage

Review each template with the client security team before apply. Templates create read-only principals only; no Ventra resources are deployed in the customer cloud beyond IAM bindings.
