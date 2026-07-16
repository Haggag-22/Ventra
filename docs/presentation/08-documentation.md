# Slide 8 — Documentation

**Sidebar:** Documentation → **AWS / Azure / GCP / Kubernetes**

## What it does

**In-app reference** — authentication setup, IAM permissions, connections, and every collector Ventra supports.

## Why it matters

Collection fails when IAM is wrong. Documentation is the single place to answer: *What does this collector need?* and *How do I deploy read-only access?*

## Structure (per platform)

| Section | Contents |
|---------|----------|
| **Authentication** | How to create credentials for Ventra |
| **Permissions** | Least-privilege IAM / RBAC policies |
| **Connections** | Linking credentials in Ventra |
| **Collectors** | One page per collector: data source, APIs, gaps, deploy templates |

## Platforms

- **AWS** — CloudTrail, GuardDuty, Config, EKS audit, S3 access logs, etc.
- **Azure** — Activity Log, Defender, AKS audit, storage analytics, etc.
- **GCP** — Audit logs, SCC, GKE audit, VPC flow, Cloud Storage access, etc.
- **Kubernetes** — API-plane vs node-plane collectors, RBAC, DaemonSet deploy

## Tied to the product

- Collector pages link to **Acquire** with that collector pre-selected
- Deployment template links (Terraform, CloudFormation, YAML) where available
- Mirrors the artifact catalog the kit builder uses

## In the walkthrough

**Close the loop.** When someone asks “what permissions does `waf` need?” — open **Documentation → AWS → Collectors → waf**.

**End of series.** Full loop: Authentication → Acquire → Kits → Run → Scans → Cases → Export → Documentation.

## Speaker notes

- Documentation is **operator-focused**, not marketing.
- Kubernetes docs cover on-prem DFIR (node + API plane) as a first-class platform.
