# Slide 1 — Authentication

**Sidebar:** Configuration → **Authentication**

## What it does

Stores **cloud credentials** Ventra uses to run live collection against your environments.

## Why it matters

Every live scan needs a trusted connection. Without authentication, you can still build kits and import offline packages—but you cannot pull telemetry directly from the cloud.

## What you do here

- **Add a provider** — AWS access keys, Azure service principal, GCP service account, or Kubernetes kubeconfig/API access
- **Name the connection** — e.g. `prod-aws-ir`, `tenant-azure-soc`
- **Test** — confirm the connection works before running a scan
- **Edit or delete** — rotate keys or retire old connections

## Supported platforms

| Platform | Typical use |
|----------|-------------|
| AWS | Account-wide or scoped IAM user/role |
| Azure | Entra ID app + subscription access |
| GCP | Service account JSON |
| Kubernetes | Cluster API access (on-prem or cloud) |

## In the walkthrough

**You start here.** Set up at least one working connection for the cloud you will demo.

**Next →** [02 — Acquire](02-acquire.md): use this connection when you run a kit.

## Speaker notes

- Emphasize **read-only** collector IAM—Ventra collects evidence; it does not remediate.
- Mention **test connection** catches permission gaps before a long scan fails halfway through.
