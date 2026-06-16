<div align="center">

# Ventra

**Cloud forensic triage — collect, normalize, investigate.**

A read-only collector runs in the client's cloud environment, pulls incident-relevant logs and
artifacts into a sealed evidence package, and hands off to an offline analyst console. No
ongoing access to the client account is required after collection.

[Architecture](docs/architecture.md) · [Evidence Package Format](docs/evidence-package-format.md) · [Operator runbook](docs/runbooks/operator.md) · [Analyst runbook](docs/runbooks/analyst.md)

</div>

---

## Overview

Ventra is an open-source toolkit for cloud incident response triage. It is built for IR teams
who need a bounded, time-scoped investigation — not a SIEM replacement or a live monitoring
platform.

The workflow has three tiers, connected by a single contract: the **Evidence Package Format
(EPF)**.

| Tier | Where it runs | Responsibility |
|------|---------------|----------------|
| **Collector** | Client cloud shell (AWS today) | Read-only acquisition, hashing, packaging |
| **Ingester** | IR workstation | Verify integrity, parse, normalize, load |
| **Console** | IR workstation or forensic VPC | Case-scoped investigation UI |

```
┌────────────────┐   sealed .tar.zst   ┌────────────────┐         ┌────────────────┐
│   COLLECTOR    │  ────────────────►  │   INGESTER     │  ────►  │    CONSOLE     │
│  cloud shell   │   manifest + hash   │  parse/normalize│  query │   analyst GUI  │
│  read-only IAM │                     │  verify/load    │         │  RBAC, offline │
└────────────────┘                     └────────────────┘         └────────────────┘
```

After collection, analysis happens entirely on evidence copies. The console makes no outbound
network calls and ships no telemetry.

## What you get

### AWS collector

Twenty read-only collectors cover the sources IR teams typically need on day one:

- **Control plane** — CloudTrail, AWS Config, logging posture
- **Identity** — IAM snapshot, account context, KMS keys, Secrets Manager metadata
- **Network & edge** — VPC Flow Logs, WAF, ELB/ALB access logs, CloudFront, Route 53 Resolver
- **Detections** — GuardDuty, Security Hub, Inspector, Macie, Detective
- **Workloads** — EC2, S3, Lambda, S3 access logs, EKS audit logs

Every source is hashed at acquisition. Disabled or empty log sources are recorded in the
manifest as gaps — missing telemetry is treated as evidence.

Review the IAM policy before any engagement:
[`docs/iam-policies/aws-collector-readonly.json`](docs/iam-policies/aws-collector-readonly.json).

### Analyst console

Investigation panels map directly to collector output:

| Panel | Focus |
|-------|--------|
| CloudTrail Timeline | API and control-plane activity |
| Security Findings | GuardDuty, Security Hub, Config, and related detections |
| Identity & Access | IAM users, roles, policies, credential posture |
| Network Activity | VPC flow volume, egress, rejected connections, flow log |
| Web & DNS | Edge access logs, WAF, DNS resolver queries |
| Data Access | S3 object-level access |
| Logs Coverage | What was collected, partial, or missing |
| Resource Inventory | EC2, S3, Lambda, and related inventory |

Role-based access control (Responder, Investigator, Data Custodian, Analyst) is enforced
server-side.

## Design principles

Ventra follows standard cloud DFIR practice, including AWS guidance on
[forensic investigation environments](https://aws.amazon.com/blogs/security/forensic-investigation-environment-strategies-in-the-aws-cloud/):

1. **Read-only at the source** — the collector IAM policy contains no mutating actions; CI enforces this.
2. **Hash on acquisition** — SHA-256 for every artifact before it leaves the account.
3. **Immutable evidence** — packages are sealed; the ingester works on copies only.
4. **Chain of custody** — operator, account, time window, tool version, and invocation are in every manifest.
5. **Separation of duties** — collection and analysis roles are distinct.
6. **Offline analysis** — the console requires no cloud connectivity after ingest.
7. **Document the gaps** — unconfigured or denied log sources are first-class outputs.

## Quick start

### 1. Collect (AWS CloudShell)

```bash
# Review the read-only policy first:
# docs/iam-policies/aws-collector-readonly.json

curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash

ventra collect aws \
  --case CASE-2026-0042 \
  --since 2026-05-01 \
  --out ~/ventra-evidence
```

The installer upgrades to the latest PyPI release on each run. Pin a version for an engagement
with `VENTRA_INSTALL_SPEC='ventra==1.0.0'`.

Collection produces a compressed evidence package and sidecar integrity files under `--out`.
Unless `--no-ingest` is passed, the package is ingested automatically into `./cases`.

Full operator steps: [`docs/runbooks/operator.md`](docs/runbooks/operator.md).

### 2. Investigate (IR workstation)

From a repository clone:

```bash
cd Ventra
ventra gui
```

On first run, `ventra gui` creates a virtual environment, installs Python and Node
dependencies, starts the FastAPI backend and Next.js frontend, and opens the console in your
browser.

You can also import a package from the Cases screen or run `ventra-ingest` manually.

Full analyst workflow: [`docs/runbooks/analyst.md`](docs/runbooks/analyst.md).

## What Ventra is not

- **Not a SIEM** — cases are scoped investigations, not always-on log pipelines.
- **Not EDR or disk forensics** — OS internals, memory, and imaging stay with dedicated tools.
- **Not a containment platform** — the collector never modifies, isolates, or terminates resources.
- **Not long-term storage** — Ventra defines the evidence format; retention is the IR team's choice.

## Repository layout

```
bin/           CloudShell install and collection scripts
collector/     Read-only acquisition (Python, boto3)
ingester/      Verify, parse, normalize, load (DuckDB / Parquet)
console/       Analyst UI (FastAPI + Next.js)
schemas/       JSON Schemas — manifest, package, unified event
docs/          EPF spec, IAM policies, runbooks, architecture
deploy/        Reference Terraform for a forensic environment
tests/         Fixtures and unit / integration tests
```

Collector modules live under `collector/aws/` by domain (`identity/`, `control_plane/`,
`network/`, `detections/`, `workloads/`). Azure and GCP packages are scaffolded for future
phases and reuse the same EPF and console.

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/architecture.md`](docs/architecture.md) | Three-tier design and EPF contract |
| [`docs/evidence-package-format.md`](docs/evidence-package-format.md) | Package structure and integrity |
| [`docs/runbooks/operator.md`](docs/runbooks/operator.md) | Running the collector |
| [`docs/runbooks/analyst.md`](docs/runbooks/analyst.md) | Console investigation workflow |
| [`docs/runbooks/data-custodian.md`](docs/runbooks/data-custodian.md) | Case import, export, deletion |
| [`docs/iam-policies/`](docs/iam-policies/) | Read-only policies per cloud |
| [`docs/threat-coverage.md`](docs/threat-coverage.md) | Detection and log source mapping |
| [`ROADMAP.md`](ROADMAP.md) | Planned phases and milestones |

## Status

Ventra is under active development. **AWS is the supported cloud today.** Azure and GCP
collectors are planned; the console and ingester are already cloud-agnostic via the unified
event schema.

See [`ROADMAP.md`](ROADMAP.md) for current phase and upcoming work.

## License

[Apache-2.0](LICENSE). No telemetry.
