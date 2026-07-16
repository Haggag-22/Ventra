# Slide 6 — Cases

**Sidebar:** Configuration → **Cases**

## What it does

**Investigation workspace** — all ingested evidence for one incident, organized for review and reporting.

## Why it matters

This is the core analyst experience. After collection, every timeline event, finding, identity snapshot, and gap lives under a single **case ID**.

## What you do here

### Cases list

- Browse cases by cloud (AWS, Azure, GCP, Kubernetes)
- See event counts, storage, time range, linked authentication
- **Open case** — lands on **Audit / CloudTrail timeline** (not an overview dashboard)
- **Import package** — ingest a `.tar.zst` bundle from offline collection
- **Import from S3** — pull handoff uploads from your IR bucket
- **Run collection** — shortcut to start another scan for this case
- **Delete case** — remove local evidence store entry

### Inside a case

| Panel | Purpose |
|-------|---------|
| **Audit Log / CloudTrail** | Primary timeline — who did what, when |
| **Security Findings** | GuardDuty, SCC, Defender-style detections |
| **Identity & IAM** | Users, roles, keys at time of collection |
| **Network** | VPC flow, firewall, load balancers |
| **Web & DNS** | ALB, CloudFront, API Gateway, resolver logs |
| **Kubernetes Audit** | EKS / GKE / AKS API audit (when collected) |
| **Data Access** | S3, storage, database access patterns |
| **Logs Coverage** | What was collected vs missing (gaps) |
| **Resource Inventory** | Cloud resource snapshot |
| **Report** | Investigation summary export |
| **Raw Evidence** | Original collector files |

## Read-only by design

Case investigation does not change cloud state—analysts search, pivot, and export.

## In the walkthrough

**After scan completes.** Open the demo case and walk the **timeline** first, then one finding and **Logs Coverage** to show gaps.

**Next →** [07 — Export](07-export.md): send events to a SIEM.

## Speaker notes

- Case ID is the **correlation key** across all sources and export batches.
- GCP case in screenshot: timeline = **Audit Log**; findings = **Security Command Center**.
