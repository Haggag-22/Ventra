# Ventra testing harness (Terraform)

Stands up an AWS environment containing **every log source the collector checks**, in either
a *logging-enabled* or *logging-disabled* state, driven by a single toggle. Pair this with the
validation loop from `obsidian/Testing Roadmap.md`:

- `enable_logging = true`  → run the collector → expect **full coverage** (no false positives)
- `enable_logging = false` → run the collector → expect **every gap caught**

> ⚠️ Creates real (mostly cheap) AWS resources and attacker-looking misconfigs. **Use a
> dedicated throwaway / sandbox account only.** Everything is tagged `Project=logging-test`.

## Layout

```
testing/terraform/
  versions.tf    terraform + provider + default_tags (Project=logging-test)
  variables.tf   the two master toggles + finer knobs
  data.tf        account/region/AZ data sources, random suffix, locals
  network.tf     VPC, 2 public subnets + firewall subnet, SGs, VPC flow logs
  buckets.tf     S3 log-destination buckets (+ policies/ACLs) and inventory buckets
  tier1.tf       CloudTrail, Config, ALB, CloudFront, S3 access, Lambda, DynamoDB, EC2, KMS, Secrets, IAM
  tier2.tf       GuardDuty, Security Hub, Detective, Inspector2, Macie, WAF, Route53 Resolver, API Gateway
  tier3.tf       Network Firewall, OpenSearch, RDS, EKS   (gated by enable_expensive)
  outputs.tf     IDs/DNS names used for the Phase 2 data-generation step
```

## Toggles

| Variable | Default | Purpose |
|---|---|---|
| `enable_logging` | `true` | Master switch: wires every log destination ON, or leaves resources present but logging OFF (gap test). |
| `enable_expensive` | `false` | Gate for Tier 3 hourly-billed resources (Network Firewall, OpenSearch, RDS, EKS). |
| `create_ec2` | `true` | The only Tier 1 hourly compute (instance + EBS + snapshot). |
| `make_bucket_public` | `false` | Attach a real anonymous public-read bucket policy. |
| `make_lambda_public` | `false` | Attach a wildcard-principal Lambda invoke permission. |
| `instance_type` | `t3.micro` | EC2 size. |
| `region` | `us-east-1` | Single deploy region. |

### Already-enabled detection services (handled automatically)

GuardDuty, Security Hub, Macie, Detective, and Inspector2 are **one-per-account/region**, so
creating one that's already on would fail. You don't need to do anything about this:
`detect.tf` runs a small **read-only** probe (`scripts/detect_services.sh`) at plan time,
figures out which are already enabled, and tells Terraform to **skip those and manage only the
rest**. The probe result is snapshotted on first apply so the toggle never flip-flops.

Requirements for the probe: the `aws` CLI on PATH with working credentials (the same ones
Terraform uses). If the probe can't reach a service it assumes "disabled".

```bash
# Just run it — already-on services are left alone:
terraform apply -var enable_logging=true
```

> Trade-off: a service that was already enabled (and thus left unmanaged) can't be turned off
> by `enable_logging=false`, so it won't produce a `service_not_enabled` gap in the OFF run.
> Disable it manually first if you specifically want to test that gap path.

## Usage

```bash
cd testing/terraform
terraform init

# Logging ON (Tier 1 + Tier 2):
terraform plan  -var enable_logging=true
terraform apply -var enable_logging=true

# Logging OFF (gap-detection run):
terraform apply -var enable_logging=false

# Include the expensive Tier 3 rows while actively testing them:
terraform apply -var enable_logging=true -var enable_expensive=true

# ALWAYS tear down when done:
terraform destroy
```

> Run `infracost breakdown --path .` before each apply if you have it installed.

## What still needs deciding / wiring (Phase 2)

This repo only builds infrastructure + logging (Phase 1). **Triggering real activity** so log
*content* actually lands (curl the ALB/CloudFront, call the API, invoke Lambda, Stratus
detonations, etc.) is the separate Phase 2 step — outputs like `alb_dns_name`,
`cloudfront_domain`, and `api_invoke_url` exist for exactly that. We'll wire the driver script
next.

## Important caveats before the first apply

- **Detection-service singletons:** handled via the `manage_*` toggles above — set the
  already-enabled ones to false so apply doesn't conflict.
- **Content vs. posture:** some sources (OpenSearch, RDS, Network Firewall, DynamoDB streams,
  API Gateway, Lambda) are only *posture-checked* by the collector — it confirms whether
  logging is configured but does not pull the content. For those, the `enable_logging` toggle
  is what you're validating, not generated log volume.
- **Log-delivery delays:** CloudTrail (~5–15 min), VPC flow / ELB / S3 access (~minutes to
  hours). Build a wait/poll step before asserting "no logs".
