<div align="center">

# Ventra

**Cloud-native incident response triage — collect, normalize, investigate.**

Ventra is an open-source toolkit for cloud forensic triage. A responder runs a single
read-only command in the client's cloud shell; Ventra pulls exactly the logs and
artifacts incident responders need into a sealed, hash-verified evidence package. The
package is handed to the IR team, normalized, and investigated in a clean, modern
analyst console — without ever touching the client environment again.

[Documentation](docs/) · [Evidence Package Format](docs/evidence-package-format.md) · [Operator Runbook](docs/runbooks/operator.md) · [Analyst Runbook](docs/runbooks/analyst.md)

</div>

---

## What Ventra is

Ventra has three loosely-coupled tiers connected by one contract — the
**Evidence Package Format (EPF)**:

| Tier | Runs where | Job |
|------|------------|-----|
| **Collector** | Client's cloud shell (AWS first) | Read-only acquisition → sealed evidence package |
| **Ingester** | IR workstation | Verify → parse → normalize → load |
| **Console** | IR workstation / forensic VPC | Case-scoped investigation GUI |

```
┌────────────────┐   sealed .tar.zst   ┌────────────────┐         ┌────────────────┐
│   COLLECTOR    │  ────────────────►  │   INGESTER     │  ────►  │    CONSOLE     │
│  cloud shell   │   manifest + sigs   │  parse/normalize│  query │   analyst GUI  │
│  read-only IAM │                     │  hash-verify    │         │  RBAC, offline │
└────────────────┘                     └────────────────┘         └────────────────┘
```

## What Ventra is **not**

- **Not a SIEM.** Cases are bounded, time-scoped investigations — not always-on pipelines.
- **Not an EDR or memory-forensics tool.** EC2 OS internals, memory, and full-disk imaging
  stay with Velociraptor / disk-image workflows. Ventra deliberately does not overlap them.
- **Not a containment tool.** The collector is **strictly read-only**. It never modifies,
  isolates, or terminates resources.
- **Not a long-term evidence vault.** Ventra defines the evidence format; storage and
  retention are the IR firm's responsibility.

## Forensic principles

Ventra is built around the guidance in AWS's
[Forensic investigation environment strategies](https://aws.amazon.com/blogs/security/forensic-investigation-environment-strategies-in-the-aws-cloud/)
and standard DFIR practice:

1. **Read-only at the source** — the collector's IAM policy contains zero mutating actions.
2. **Hash on acquisition** — SHA-256 every artifact before it leaves the source account.
3. **Immutable evidence** — packages are sealed and signed; the ingester works on copies.
4. **Chain of custody is first-class** — operator, timestamps, account, tool version, and
   invocation are captured in every manifest.
5. **Separation of duties** — Responder, Investigator, Data Custodian, Analyst map to the
   console's RBAC model.
6. **Isolated analysis** — the console makes **no outbound calls** and ships no telemetry.
7. **Document the gaps** — a disabled or empty log source is itself evidence.

## Quick start

### Collector (in AWS CloudShell)

```bash
# Review the read-only IAM policy first: docs/iam-policies/aws-collector-readonly.json
# AWS CloudShell — one-time install (skips if already set up):
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
ventra collect aws --case CASE-2026-0042 --out ~/ventra-evidence
```

### Ingester + Console (on the IR workstation)

From a clone — one command, no prior setup:

```bash
cd Ventra
python3 -m collector dev    # first run installs .venv + deps + npm, opens browser
# or, after any pip install of ventra:
ventra dev                  # same thing
ventra gui                  # production — Docker Compose (or ventra gui --local)
```

`ventra dev` creates `.venv`, installs Python and npm dependencies if needed, then starts
the console with hot reload. Edit code, save, refresh the browser.

```bash
# then drag the evidence package into the Cases panel, or:
ventra-ingest ./case-CASE-2026-0042-*.tar.zst --case-store ./cases
```

See the [Operator Runbook](docs/runbooks/operator.md) and
[Analyst Runbook](docs/runbooks/analyst.md) for full walkthroughs.

## Repository layout

```
bin/         CloudShell scripts (install-cloudshell.sh, aws_cloudshell.sh, verify_signature.sh)
collector/   Acquisition tool (Python, boto3) — runs in the client cloud shell
ingester/    Verify → parse → normalize → load (Python, DuckDB/Parquet)
console/     Analyst GUI — FastAPI backend + Next.js frontend
schemas/     JSON Schemas: manifest, package, unified event
docs/        EPF spec, IAM policies, runbooks, threat coverage
deploy/      Docker, Compose, Terraform reference forensics environment
tests/       Fixtures + unit/integration/e2e
pyproject.toml   ventra package (pip install from repo root)
```

### Collector layout

```
collector/
  cli.py                 entry point (`ventra collect`) — runs every registered collector
  lib/                   models, base, chain_of_custody, packaging, transport
  aws/                   registry, runner, client_factory + collector modules
    identity/            iam, sts, account, kms, secrets
    control_plane/       cloudtrail, config
    network/             vpc_flow, waf
    detections/          guardduty, securityhub, macie, detective
    workloads/           ec2, s3, lambda
  azure/                 scaffolded for later phases
  gcp/                   scaffolded for later phases
  tools/                 verify_readonly static guard
```

Design rules: **read-only** (zero mutating API calls), **hash on acquisition**, pure collectors
that return `SourceResult`, and **gaps are evidence** (disabled sources recorded in the manifest).
The `readonly-guard` CI check and IAM policies in `docs/iam-policies/` enforce the first rule.

## Status

Ventra is in active development. AWS is the first supported cloud; Azure and GCP are
scaffolded for later phases that reuse the same EPF and console unchanged. See the
[roadmap](ROADMAP.md).

## License

[Apache-2.0](LICENSE). No telemetry, ever. Releases are signed — see [SECURITY.md](SECURITY.md).
