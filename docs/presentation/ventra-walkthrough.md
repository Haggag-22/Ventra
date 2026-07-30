# Ventra product walkthrough

**Presentation deck** — one slide per left-sidebar feature, in demo order.

**Flow:** Authentication → Acquire → Collection Kits → Run kit → Scans → Cases → Export → Documentation

---

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

**Next →** Slide 2 — Acquire

## Speaker notes

- Emphasize **read-only** collector IAM—Ventra collects evidence; it does not remediate.
- Mention **test connection** catches permission gaps before a long scan fails halfway through.

---

# Slide 2 — Acquire

**Sidebar:** Configuration → **Acquire**

## What it does

**Kit builder** — choose which collectors to run, set case scope, parameters, and how evidence gets back to you.

## Why it matters

This is where you define *what* to collect for an investigation: CloudTrail vs GuardDuty vs VPC flow, baseline IR pack vs custom cart, time window, regions, and handoff destination.

## What you do here

1. **Pick a platform** — AWS, Azure, GCP, or Kubernetes
2. **Set case ID** — ties all artifacts to one investigation (e.g. `CASE-2026-0042`)
3. **Select collectors** — browse by category or load a baseline pack
4. **Tune parameters** — lookback days, regions, resource filters, GCP log backend (if needed)
5. **Choose handoff** — how the client or Ventra server receives the bundle:
   - **Upload to my IR bucket** — kit writes to your S3 prefix; you import from S3
   - **Presigned URL** — one-time upload URL for the client (no long-lived bucket IAM on their side)
6. **Save as Collection Kit** or **Run** / **Download Kit** immediately

## Two deployment modes

| Mode | Who runs collectors | Typical scenario |
|------|---------------------|------------------|
| **Live scan** | Ventra server (uses Authentication) | Analyst machine or IR VPC with cloud API access |
| **Offline kit** | Customer downloads ZIP/script | Client environment; results uploaded via handoff |

## In the walkthrough

**After Authentication.** Build the kit you will demo—often a baseline IR pack for one cloud.

**Next →** Slide 3 — Collection Kits

## Speaker notes

- Acquire is the **shopping cart** for forensic sources—not the investigation UI.
- Enterprise vs platform profiles affect packaging (single cloud vs multi-cloud kits).

---

# Slide 3 — Collection Kits

**Sidebar:** Configuration → **Collection Kits**

## What it does

**Saved, reusable collection recipes** — named kits you can run again without rebuilding from scratch.

## Why it matters

IR teams repeat the same collection playbook across cases. Kits encode *which* collectors, *which* platform, and default scope so the next incident starts in minutes, not hours.

## What you do here

- **View all kits** — name, cloud, collector count
- **Run** — start a live scan with the saved definition (opens run wizard: connection, case ID, scope)
- **Download Kit** — generate offline acquisition package for the client
- **Edit** — opens Acquire with that kit loaded
- **Delete** — remove obsolete kits

## Kit = snapshot of Acquire

Each kit stores:

- Platform (AWS / Azure / GCP / Kubernetes)
- Selected collectors and artifact parameters
- Handoff / transport preferences
- Deployment profile (when applicable)

## In the walkthrough

**After you save from Acquire.** Show one named kit—e.g. `baseline-ir-aws` or your demo case kit.

**Next →** Slide 4 — Running a kit

## Speaker notes

- Kits are **not cases**—they are templates. The case is created when a run completes and evidence is ingested.
- Good naming: `{customer}-{cloud}-{playbook}` or `CASE-template-baseline-gcp`.

---

# Slide 4 — Running a kit

**From:** Collection Kits → **Run** (or Acquire → **Run collection**)

## What it does

**Starts acquisition** — either a **live scan** on the Ventra server or preparation of an **offline kit** for download.

## Why it matters

This is the handoff from *configuration* to *execution*. Until a kit runs (or an offline bundle is ingested), there is no case to investigate.

## Live scan flow

1. Click **Run** on a kit (or **Run collection** in Acquire)
2. **Select authentication** — connection from slide 1
3. **Confirm case ID** — new or existing investigation id
4. **Adjust scope** — time range, regions, optional resource filters
5. **Submit** — Ventra queues collectors and calls cloud APIs
6. Redirect to **Scans** — live run detail with per-collector progress

## Offline kit flow

1. Click **Download Kit** on a kit
2. Client runs the package in *their* environment (no Ventra cloud credentials on your server)
3. Upload result via **IR bucket** or **presigned URL** (configured in Acquire)
4. **Import** on Cases — package file or **Import from S3**

## What gets produced

- Raw collector outputs (archives, JSON, logs)
- Manifest describing sources, gaps, and parameters
- Ingested **case** ready for timeline and findings

## In the walkthrough

**The action step.** Run a live scan against your lab account or import a pre-built demo case if offline.

**Next →** Slide 5 — Scans

## Speaker notes

- Live scan = you see progress in real time; offline = client air-gap friendly.
- Failed collectors still land as **gaps** in the manifest—missing telemetry is itself evidence.

---

# Slide 5 — Scans

**Sidebar:** Configuration → **Scans**

## What it does

**Live collection monitor** — every run, its status, duration, and per-collector results.

## Why it matters

Cloud collection can take minutes to hours. Scans is where analysts watch progress, diagnose failures, and jump to the case when evidence is ready.

## What you do here

### Scans list

- Filter: **All / Running / Completed / Failed / Cancelled**
- See case ID, platform, collector progress, timestamps
- **View** — open run detail
- **Rerun** — same kit + scope, new run id
- **Cancel** — stop an in-flight live scan

### Run detail (live)

- **Status badge** — pending, running, completed, failed, cancelled
- **Collector matrix** — each source: running, collected, empty, error, gap
- **Event log** — streaming collector messages (SSE)
- **Open case** — when ingest finished and case exists
- **Elapsed time** and artifact counts

## “Live scan” in practice

While status is **Running**:

- Matrix rows flip from pending → complete as APIs return
- WAF / CloudFront / S3 log collectors may show gaps until logs land (normal)
- You can leave the page and return—Scans list still shows active runs

## In the walkthrough

**After starting a kit.** Keep this page open until the run shows **Completed**, then **Open case**.

**Next →** Slide 6 — Cases

## Speaker notes

- Scans = **operations**; Cases = **investigation**.
- Demo tip: use a pre-ingested case if the live run is slow; show Scans on a shorter lab run separately.

---

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

**Next →** Slide 7 — Export

## Speaker notes

- Case ID is the **correlation key** across all sources and export batches.
- GCP: timeline = **Audit Log**; findings = **Security Command Center**.

---

# Slide 7 — Export

**Sidebar:** Configuration → **Export**

## What it does

**SIEM handoff** — export normalized, case-scoped events to Elastic, Splunk, or generic NDJSON.

## Why it matters

Ventra is the collection and first-pass analysis layer. Most teams still replay timelines in Elastic or Splunk for correlation, alerting, and long-term retention.

## What you do here

1. **Select cases** — one or many investigations
2. **Choose target format**:

   | Target | Output |
   |--------|--------|
   | **Elastic** | ECS-shaped NDJSON + starter index template |
   | **Splunk** | CIM-normalized HEC NDJSON |
   | **Generic NDJSON** | One normalized event per line, unshaped |

3. **Filter sources** (optional) — export only CloudTrail, only findings, etc.
4. **Review counts** — events per source, approximate size
5. **Export** — download archive or stream batch to your pipeline

## What gets exported

- Normalized timeline events (not raw collector blobs)
- Per-source event counts from ingestion stats
- Case metadata for index routing (`case_id`, cloud, time bounds)

## In the walkthrough

**After showing a case.** Export one case to **Elastic** or **NDJSON** and mention Splunk HEC for Splunk shops.

**Next →** Slide 8 — Documentation

## Speaker notes

- Export is **outbound** from Ventra’s case store—not live cloud polling.
- Teams often export subsets (audit only) to control SIEM volume.

---

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

**End of series.**

## Speaker notes

- Documentation is **operator-focused**, not marketing.
- Kubernetes docs cover on-prem DFIR (node + API plane) as a first-class platform.
