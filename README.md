# Ventra

**Cloud forensic triage: collect, normalize, investigate.**

Ventra is a read only cloud incident response toolkit. A collector runs in the client's cloud
environment (AWS CloudShell, Azure Cloud Shell, GCP Cloud Shell, or an IR workstation), gathers
incident relevant logs and artifacts, seals them into a hashed evidence package, and hands off to
an offline analyst console. No ongoing access to the client account is required after collection.

[Architecture](docs/architecture.md) · [Evidence Package Format](docs/evidence-package-format.md) · [Operator runbook](docs/runbooks/operator.md) · [Analyst runbook](docs/runbooks/analyst.md)

---

## About Ventra

Ventra streamlines collection of the data IR teams need during a cloud investigation. It is built
for bounded, time scoped triage: not a SIEM replacement and not a live monitoring platform.

The workflow has three tiers, connected by a single contract: the **Evidence Package Format
(EPF)**.

| Tier | Where it runs | Responsibility |
|------|---------------|----------------|
| **Collector** | Client cloud shell or IR workstation | Read only acquisition, hashing, packaging |
| **Ingester** | IR workstation | Verify integrity, parse, normalize, load |
| **Console** | IR workstation or forensic VPC | Case scoped investigation UI |

```
┌────────────────┐   sealed .tar.zst   ┌────────────────┐         ┌────────────────┐
│   COLLECTOR    │  ────────────────►  │   INGESTER     │  ────►  │    CONSOLE     │
│  cloud shell   │   manifest + hash   │  parse/normalize│  query │   analyst GUI  │
│  read only IAM │                     │  verify/load    │         │  RBAC, offline │
└────────────────┘                     └────────────────┘         └────────────────┘
```

Every artifact is SHA 256 hashed at acquisition. Disabled, empty, or denied log sources are
recorded in the manifest as **gaps**: missing telemetry is treated as evidence. After collection,
analysis happens entirely on evidence copies; the console makes no outbound network calls and
ships no telemetry.

Artifacts are declared in YAML; collectors execute in Python under a shared engine. The **Acquire**
tab in the console lets an IR lead browse the catalog, preview narrowed IAM, choose a deployment
profile, and download an operator kit without using the CLI.

---

## Supported data sources

Ventra ships **60+ artifact definitions** across **AWS**, **Azure**, and **GCP**, plus curated
**baseline IR packs** per cloud (`baseline-ir-aws`, `baseline-ir-azure`, `baseline-ir-gcp`).

### AWS log sources

| Source | Description |
|--------|-------------|
| **CloudTrail** | Management, data, insight, and network activity events; trail config; S3 log integrity validation |
| **AWS Config** | Recorder state and compliance findings |
| **VPC Flow Logs** | Flow log configuration and flow records from CloudWatch or S3 |
| **WAF** | WAFv2 Web ACL configs, logging configuration, sampled requests |
| **ELB/ALB Access Logs** | Access logs from S3 delivery buckets and per LB logging posture |
| **CloudFront Access Logs** | Standard access logs from S3 and per distribution logging posture |
| **Route 53 Resolver Query Logs** | DNS query logs from S3 or CloudWatch destinations |
| **S3 Access Logs** | Server access logs from logging target buckets and per bucket posture |
| **EKS Audit Logs** | Kubernetes API server audit logs from CloudWatch and cluster posture |
| **GuardDuty** | Findings, detector config, suppression filters |
| **Security Hub** | ASFF findings and enabled standards |
| **Inspector2** | Vulnerability and network reachability findings |
| **Macie** | Sensitive data and policy findings |
| **Detective** | Graph membership and open investigations |

### AWS inventory and posture

| Source | Description |
|--------|-------------|
| **Account** | Account, organization, region, and operator context |
| **IAM** | Users, roles, groups, policies, access keys, credential report |
| **KMS** | Key inventory, key policies, and grants |
| **Secrets Manager** | Metadata (never secret values), rotation, resource policies |
| **EC2 / EBS** | Instance and volume inventory; snapshot share/copy evidence trail |
| **S3** | Bucket inventory, public exposure, policies, logging, Object Lock |
| **Lambda** | Function inventory, resource policies, redacted environment config |
| **Log posture** | Presence detection for sources without a dedicated collector yet (API Gateway, Lambda log groups, OpenSearch, RDS, DynamoDB Streams, Network Firewall) |

Review the read only IAM policy before any engagement:
[`docs/iam-policies/aws-collector-readonly.json`](docs/iam-policies/aws-collector-readonly.json).

### Azure

Review read only permissions before any engagement:

- ARM: [`docs/iam-policies/azure-collector-readonly.json`](docs/iam-policies/azure-collector-readonly.json)
- Microsoft Graph: [`docs/iam-policies/azure-collector-graph.json`](docs/iam-policies/azure-collector-graph.json)
- M365 / Exchange UAL search: [`docs/iam-policies/azure-collector-m365.json`](docs/iam-policies/azure-collector-m365.json)

#### Identity, M365, and control plane

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `subscription` | Tenant, subscription, and operator context | Resource Inventory |
| `entra_signin` | Entra ID sign in logs (P1/P2 required) | Activity Log Timeline |
| `entra_audit` | Entra ID directory audit logs | Activity Log Timeline |
| `entra_directory` | Users, groups, applications, service principals snapshot | Identity & Access |
| `rbac` | Azure RBAC role definitions and assignments | Identity & Access |
| `activity_log` | Azure Activity Log: ARM control plane operations (89d default) | Activity Log Timeline |
| `unified_audit` | M365 Unified Audit Log via Management API (~7d) | Activity Log Timeline |
| `unified_audit_search` | M365 UAL via the search API (90d default) | Activity Log Timeline |
| `oauth_consent` | OAuth2 permission grants inventory | Activity Log Timeline |
| `defender` | Microsoft Defender for Cloud security alerts | Security Findings |
| `resource_graph` | Cross subscription ARM inventory snapshot | Resource Inventory |
| `diag_posture` | Diagnostic settings routing posture (Storage / LA / none) | Logs Coverage |

#### Network, data access, and Log Analytics

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `vnet_flow` | VNet flow logs from delivery Storage account | Network Activity |
| `nsg_flow` | Legacy NSG flow logs from Storage | Network Activity |
| `azure_firewall` | Azure Firewall application/network/DNS logs (Storage diagnostics) | Network Activity |
| `app_gateway` | Application Gateway access, performance, and WAF logs | Web & DNS |
| `front_door` | Front Door / CDN access and WAF logs | Web & DNS |
| `dns` | Public/private DNS and resolver query logs | Web & DNS |
| `storage_access` | Storage account read/write/delete access logs | Data Access |
| `key_vault` | Key Vault audit events | Data Access |
| `aks_audit` | AKS kube audit logs from Storage diagnostics | Kubernetes Audit |
| `log_analytics` | Same diagnostic categories when routed to Log Analytics workspaces | Network / Web / Data panels |

Collect a subset with `--collectors`, for example:
`ventra collect azure --case CASE-2026-0042 --collectors activity_log,entra_signin`.

### GCP

GCP collectors cover Cloud Audit Logs (admin, system, data access), SCC findings, VPC flow and
firewall logs, load balancer and API Gateway access, Cloud Storage access, IAM policy bindings,
login audit, and project inventory. Run the baseline pack:

```bash
ventra collect gcp --pack baseline-ir-gcp --case CASE-2026-0042 --project my-project --out ~/ventra-evidence
```

See [`docs/artifacts.md`](docs/artifacts.md) for the full GCP catalog and
[`artifacts/packs/baseline-ir-gcp.yaml`](artifacts/packs/baseline-ir-gcp.yaml) for the curated IR
bundle.

---

## Analyst console

After ingest, investigation panels map directly to collector output. The console operates in two
modes:

| Mode | Purpose |
|------|---------|
| **Investigate** | Import evidence packages, query normalized events, review coverage and inventory |
| **Acquire** | Browse artifacts and packs, preview IAM, build operator kits, operator handoff |

### Investigate panels

| Panel | Focus |
|-------|--------|
| **CloudTrail Timeline** | API and control plane activity (CloudTrail, Activity Log, Entra, Cloud Audit Logs) |
| **Security Findings** | GuardDuty, Security Hub, Defender, SCC, and related detections |
| **Identity & Access** | IAM / RBAC users, roles, policies, credential posture |
| **Network Activity** | VPC / NSG / VNet flow volume, egress, rejected connections, VPC scoped flow table |
| **Web & DNS** | Edge access logs, WAF, DNS resolver queries |
| **Kubernetes Audit** | EKS and AKS API server audit logs |
| **Data Access** | S3, CloudTrail data events, storage and Key Vault access |
| **Search** | Cross source event search with facets |
| **Logs Coverage** | What was collected, partial, or missing |
| **Resource Inventory** | EC2, S3, Lambda, ARM, GCP project resources, and related inventory |
| **Raw Evidence** | Browse sealed source files from the package |

Role based access control (Responder, Investigator, Data Custodian, Analyst) is enforced
server side. Investigators can import cases and export evidence bundles for downstream SIEM
workflows (Elastic NDJSON export and Logstash pipelines under `ingester/pipelines/`).

---

## Usage

### Requirements

- **Python 3.11+**
- **AWS:** credentials with the read only collector policy attached (CloudShell works out of the box)
- **Azure:** `az login` and `pip install 'ventra[azure]'` (or `ventra[dev]` from a clone)
- **GCP:** Application default credentials or a service account; `pip install 'ventra[gcp]'` or `ventra[dev]`
- **Console:** Node.js 18+ (installed automatically by `ventra gui`)

### Install

From PyPI:

```bash
pip install ventra

# Azure collectors
pip install 'ventra[azure]'

# GCP collectors
pip install 'ventra[gcp]'

# Full development / console stack
pip install 'ventra[dev]'
```

From a repository clone:

```bash
git clone https://github.com/Haggag-22/Ventra.git
cd Ventra
pip install -e '.[dev]'
```

### AWS CloudShell (recommended for client side collection)

```bash
# Review the read only policy first:
# docs/iam-policies/aws-collector-readonly.json

curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash

ventra collect aws \
  --case CASE-2026-0042 \
  --since 2026-05-01 \
  --out ~/ventra-evidence
```

The installer upgrades to the latest PyPI release on each run. Pin a version for an engagement
with `VENTRA_INSTALL_SPEC='ventra==1.0.0'`.

### Azure (host / IR workstation)

Use a client service principal from your machine. Flags override ``AZURE_*`` env vars:

```bash
ventra collect azure \
  --case CASE-2026-0042 \
  --tenant-id "<tenant-id>" \
  --client-id "<app-client-id>" \
  --client-secret "<secret>" \
  --subscription "<subscription-id>" \
  --since 2026-05-01 \
  --out ~/ventra-evidence
```

Certificate auth instead of a secret:

```bash
ventra collect azure \
  --case CASE-2026-0042 \
  --tenant-id "<tenant-id>" \
  --client-id "<app-client-id>" \
  --client-certificate /path/to/sp.pem \
  --subscription "<subscription-id>" \
  --out ~/ventra-evidence
```

Or set ``AZURE_TENANT_ID``, ``AZURE_CLIENT_ID``, and ``AZURE_CLIENT_SECRET`` (or
``AZURE_CLIENT_CERTIFICATE_PATH``) in the environment and omit the flags.

### GCP (host / IR workstation)

```bash
ventra collect gcp \
  --pack baseline-ir-gcp \
  --case CASE-2026-0042 \
  --project my-gcp-project \
  --since 2026-05-01 \
  --out ~/ventra-evidence
```

### AWS (host / IR workstation)

Use a named profile from ``~/.aws/credentials``:

```bash
ventra collect aws \
  --case CASE-2026-0042 \
  --profile client-readonly \
  --since 2026-05-01 \
  --out ~/ventra-evidence
```

``--profile`` is equivalent to ``AWS_PROFILE`` for that run. The profile name is recorded in
the package manifest (not the secret key).

### Operator kits and packs

Build a kit zip from the CLI or the **Acquire** tab in the console:

```bash
ventra kit build \
  --cloud aws \
  --pack baseline-ir-aws \
  --case CASE-2026-0042 \
  --out kit.zip
```

The kit contains `acquisition.yaml`, artifact YAML copies, narrowed IAM, and a bootstrap script
for the operator to run in Cloud Shell. See [`docs/artifacts.md`](docs/artifacts.md).

### Investigate (IR workstation)

```bash
ventra gui
```

On first run, `ventra gui` creates a virtual environment, installs Python and Node
dependencies, starts the FastAPI backend and Next.js frontend, and opens the console in your
browser. Import a package from the Cases screen, use **Import from S3** for enterprise handoff,
or run `ventra-ingest` manually.

Export a case to Elastic friendly NDJSON:

```bash
ventra-export --case-dir ./cases/CASE-2026-0042 --out ./export
```

Full operator steps: [`docs/runbooks/operator.md`](docs/runbooks/operator.md)  
Full analyst workflow: [`docs/runbooks/analyst.md`](docs/runbooks/analyst.md)

---

## Available collectors

Running `ventra collect aws`, `ventra collect azure`, or `ventra collect gcp` executes every
registered collector for that cloud unless you pass `--collectors`, `--pack`, or `--acquisition`.
List them with:

```bash
ventra collect aws --list-collectors
ventra collect azure --list-collectors
ventra collect gcp --list-collectors
ventra collect aws --list-packs
ventra artifacts list --cloud gcp
```

### Control plane and audit

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `cloudtrail` | CloudTrail trail config; management, insight, data, and network activity events; S3 log integrity validation | CloudTrail Timeline |
| `config` | AWS Config recorder state and compliance findings | Security Findings |
| `activity_log` | Azure Activity Log: subscription control plane operations | CloudTrail Timeline |
| `entra_signin` | Entra ID sign in logs | CloudTrail Timeline |
| `entra_audit` | Entra ID audit logs: directory and application changes | CloudTrail Timeline |
| `cloud_audit_admin` | GCP Admin Activity audit logs | CloudTrail Timeline |
| `cloud_audit_data` | GCP Data Access audit logs | Data Access |
| `log_posture` | Logging posture for API Gateway, Lambda, OpenSearch, RDS, DynamoDB Streams, Network Firewall | Logs Coverage |

### Identity and access

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `account` | AWS account, organization, region, and operator context | Resource Inventory |
| `subscription` | Azure subscription, tenant, region, and operator context | Resource Inventory |
| `project` | GCP project, organization, and operator context | Resource Inventory |
| `iam` | IAM users, roles, groups, policies, access keys, credential report | Identity & Access |
| `iam_policy` | GCP IAM policy bindings | Identity & Access |
| `rbac` | Azure RBAC role definitions and assignments | Identity & Access |
| `kms` | KMS key inventory, key policies, and grants | Identity & Access |
| `secrets` | Secrets Manager metadata (never values), rotation, resource policies | Identity & Access |

### Network and edge

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `vpc_flow` | VPC Flow Logs configuration and flow records | Network Activity |
| `vnet_flow` | Azure VNet flow logs from storage | Network Activity |
| `nsg_flow` | NSG flow log configuration and flow records from storage | Network Activity |
| `firewall_logs` | GCP VPC firewall rule logs | Network Activity |
| `waf` | WAFv2 Web ACL configs, logging configuration, sampled requests | Web & DNS |
| `elb_alb` | ELB/ALB access logs from S3 and per LB logging posture | Web & DNS |
| `cloudfront` | CloudFront standard access logs from S3 and logging posture | Web & DNS |
| `route53_resolver` | Route 53 Resolver DNS query logs from S3 or CloudWatch | Web & DNS |
| `load_balancer` | GCP HTTP(S) load balancer access logs | Web & DNS |

### Detections and findings

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `guardduty` | GuardDuty findings, detector config, suppression filters | Security Findings |
| `securityhub` | Security Hub ASFF findings and enabled standards | Security Findings |
| `inspector2` | Inspector2 vulnerability and network reachability findings | Security Findings |
| `macie` | Macie sensitive data and policy findings | Security Findings |
| `detective` | Detective graph config and open investigations | Security Findings |
| `defender` | Microsoft Defender for Cloud security alerts | Security Findings |
| `scc_findings` | GCP Security Command Center findings | Security Findings |

### Workloads and data access

| Collector | Description | Console panel |
|-----------|-------------|---------------|
| `ec2` | EC2/EBS inventory and snapshot share/copy evidence trail | Resource Inventory |
| `s3` | S3 bucket inventory, public exposure, policies, logging, Object Lock | Resource Inventory |
| `lambda` | Lambda function inventory, resource policies, redacted env config | Resource Inventory |
| `s3_access` | S3 server access logs and per bucket logging posture | Data Access |
| `eks_audit` | EKS Kubernetes API server audit logs and cluster posture | Kubernetes Audit |
| `storage_access` | Azure Storage or GCS bucket access logs | Data Access |

### CLI reference

| Command | Description |
|---------|-------------|
| `ventra collect aws` | Run AWS collectors and seal an evidence package |
| `ventra collect azure` | Run Azure collectors and seal an evidence package |
| `ventra collect gcp` | Run GCP collectors and seal an evidence package |
| `ventra collect <cloud> --list-collectors` | List registered collectors |
| `ventra collect <cloud> --list-packs` | List curated IR packs |
| `ventra kit build` | Build an operator kit zip from artifacts or a pack |
| `ventra artifacts list` | Browse the artifact catalog |
| `ventra artifacts validate` | Validate artifact YAML (CI gate) |
| `ventra gui` | Start the analyst console locally |
| `ventra-ingest <package.tar.zst>` | Ingest a package into the case store |
| `ventra-export --case-dir … --out …` | Export ingested events to Elastic NDJSON |

Common flags: `--case`, `--since`, `--until`, `--regions`, `--out`, `--no-ingest`, `--transport`, `--collectors`, `--pack`, `--acquisition`.

**AWS host auth:** `--profile <name>` (or `AWS_PROFILE`). **Azure host auth:** `--tenant-id`, `--client-id`, `--client-secret` or `--client-certificate`, plus `--subscription` (comma separated). Env vars `AZURE_*` work when flags are omitted. **GCP:** `--project` and application default credentials or a service account key.

For M365 UAL filters: `--ual-users`, `--ual-operations`, and related `--ual-*` flags.

---

## What Ventra is not

- **Not a SIEM:** cases are scoped investigations, not always on log pipelines.
- **Not EDR or disk forensics:** OS internals, memory, and imaging stay with dedicated tools.
- **Not a containment platform:** the collector never modifies, isolates, or terminates resources.
- **Not long term storage:** Ventra defines the evidence format; retention is the IR team's choice.

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/architecture.md`](docs/architecture.md) | Three tier design and EPF contract |
| [`docs/evidence-package-format.md`](docs/evidence-package-format.md) | Package structure and integrity |
| [`docs/artifacts.md`](docs/artifacts.md) | YAML catalog, packs, kit builder, Acquire API |
| [`docs/runbooks/operator.md`](docs/runbooks/operator.md) | Running the collector |
| [`docs/runbooks/analyst.md`](docs/runbooks/analyst.md) | Console investigation workflow |
| [`docs/runbooks/data-custodian.md`](docs/runbooks/data-custodian.md) | Case import, export, deletion |
| [`docs/iam-policies/`](docs/iam-policies/) | Read only policies per cloud |
| [`docs/threat-coverage.md`](docs/threat-coverage.md) | Detection and log source mapping |
| [`ingester/pipelines/elastic/README.md`](ingester/pipelines/elastic/README.md) | Elastic NDJSON export and Logstash runbook |
| [`ROADMAP.md`](ROADMAP.md) | Planned phases and milestones |

---

## Status

**AWS**, **Azure**, and **GCP** collectors are supported end to end: demo fixtures, ingest, and
console panels. The **Acquire** builder (artifact library, packs, IAM preview, operator handoff) is
shipped. **Enterprise scale** work (streaming collectors, S3 ingest workers, SSO, managed
collection workers) is in progress under Track D.

See [`ROADMAP.md`](ROADMAP.md) and [`obsidian/Ventra Enterprise Roadmap.md`](obsidian/Ventra%20Enterprise%20Roadmap.md) for current phase detail.

---

## License

[Apache-2.0](LICENSE). No telemetry.
