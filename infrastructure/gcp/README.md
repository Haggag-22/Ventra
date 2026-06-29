# GCP collector lab

Terraform stack that stands up a live GCP environment exercising **all 25 Ventra GCP
collectors**. Deploy it, let the lab VMs generate a few minutes of traffic, then run the
`baseline-ir-gcp` acquire pack against the project.

## Naming

Every resource name is **letters only — no dashes, no numbers** (e.g. `ventravpc`,
`ventrasubnet`, `ventrabackend`). The prefix is `var.name_prefix` (default `ventra`).

The only place a derived suffix appears is where GCP requires a *globally unique* name —
Cloud Storage buckets, the Cloud SQL instance, and the API Gateway config id. Those append
`local.token`, a letters-only token derived from your project id (all digits and dashes
stripped), so they stay unique without introducing numbers or dashes.

## Collector coverage

| Collector | What backs it |
|-----------|---------------|
| project | The project + enabled APIs |
| iam_policy | Lab service account, user-managed key, custom read-only role, project bindings |
| cloud_audit_admin | Admin Activity logs (every apply/admin call) |
| cloud_audit_system | System Event logs (VM lifecycle) |
| cloud_audit_data | Data Access logs (audit config: ADMIN_READ/DATA_READ/DATA_WRITE) |
| logging_posture | Subnet flow logs + firewall logging + audit log sink presence |
| login_events | Data Access audit config (see caveat below) |
| vpc_flow | Subnet with flow logs + VM traffic |
| firewall_logs | Firewall rules with logging + VM traffic |
| cloud_nat | Cloud Router + Cloud NAT (logging ALL) + private VM egress |
| network_posture | VPC, subnets, firewall rules, custom route, packet mirroring policy |
| load_balancer | External HTTP LB with access logging + traffic |
| api_gateway | API Gateway in front of the Cloud Function |
| cloud_dns | Private DNS zone + DNS policy with query logging + VM lookups |
| cloud_armor | Cloud Armor security policy attached to the LB backend |
| vm_logs | Two VMs running the Cloud Ops Agent |
| gce | Instances, attached disk, snapshot, NICs |
| cloud_functions | Cloud Functions Gen2 + invocations from the traffic generator |
| gke_audit | Zonal GKE cluster with API-server logging |
| storage_access | App bucket + access logging (see caveat below) |
| bigquery_audit | BigQuery dataset + table + query jobs from the VM |
| cloud_sql | Cloud SQL for PostgreSQL with connection/statement logging |
| secret_manager | Secret + version, read by the VM on a timer |
| scc_findings | Org-level SCC (toggle, needs `org_id`) |
| cloud_monitoring | Alert policy + email notification channel |

## Deploy

```bash
cd infrastructure/gcp
cp terraform.tfvars.example terraform.tfvars   # set project_id
terraform init
terraform apply
```

The two lab VMs run a systemd timer every 5 minutes that curls the load balancer and Cloud
Function, performs DNS lookups, reads the secret, lists the bucket, and runs a BigQuery
query — so the log-based collectors have records. Give it ~10–15 minutes after apply before
collecting.

## Acquire

Pack `baseline-ir-gcp` (`artifacts/packs/baseline-ir-gcp.yaml`). The minimum read-only IAM
the collectors need is in `docs/iam-policies/gcp-collector-readonly.json`, and this lab also
creates that exact role as `ventracollectorreadonly`.

## Cost & teardown

GKE and Cloud SQL are the main cost items. Disable any component in `terraform.tfvars`
(`enable_gke`, `enable_cloud_sql`, `enable_bigquery`, …) to cut cost. Everything has
`force_destroy` / `deletion_protection = false`, so:

```bash
terraform destroy
```

removes the whole lab, including the user-managed service account key (stored in state — a
reason to destroy the lab when finished).

## Caveats (collector behavior in a fresh lab)

- **login_events** filters Data Access logs for `google.login` /
  `CreateServiceAccountKey`. `google.login` comes from real Console/Workspace sign-ins, so
  this collector is usually sparse until a human signs in to the project.
- **storage_access** reads the `storage.googleapis.com%2Frequests` log stream. Cloud Storage
  data-plane activity is reliably captured by **cloud_audit_data** here; if that dedicated
  stream is empty in your project, storage_access can come back empty even though the bucket
  is being accessed.
- **cloud_monitoring** has the alert policy and channel, but an actual incident only logs
  when the alert fires (VM CPU > 90% for 60s).
- **cloud_sql** logs connection/statement activity once something connects — use Cloud SQL
  Studio or the Auth Proxy with the `ventrauser` credentials to generate query logs.
- **scc_findings** is organization-scoped; set `org_id` and have SCC enabled at the org.
