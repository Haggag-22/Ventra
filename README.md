# Ventra

**Read-only cloud forensic triage for AWS, Azure, GCP and Kubernetes.**

Ventra helps incident responders collect the logs and snapshots they need from a cloud account,
seal them into a hashed evidence package, and investigate offline in a local web console. It
never changes anything in the account it collects from, and nothing leaves your machine.

You do everything from the console: connect a cloud account, build a **Collection Kit** in
**Acquire**, run it (from the console or a terminal), then investigate the case.

```
 1. Build a kit          2. Run the kit                   3. Investigate
┌──────────────┐       ┌───────────────────────────┐     ┌──────────────────┐
│  Console →   │  ──►  │ Console "Run"             │ ──► │ Console → Cases  │
│  Acquire     │       │   or                      │     │ timeline, IAM,   │
│  (save kit)  │       │ terminal: ventra run .kit │     │ network, gaps…   │
└──────────────┘       └───────────────────────────┘     └──────────────────┘
```

---

## Install

You need **Python 3.11+**. The easiest way is [uv](https://docs.astral.sh/uv/)
(`brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`):

```bash
uv tool install ventra
ventra --version
```

No uv? Use `pipx install ventra` instead.

The console is included in the package. You don't need Node.js or a clone of this repo.

---

## Quickstart

### 1. Open the console

```bash
ventra gui
```

Your browser opens at `http://127.0.0.1:8000` (Ventra picks the next free port if 8000 is
busy). The console only listens on your own machine.

### 2. Add a cloud connection

Go to **Configuration → Authentication** and add a connection for the cloud you are
investigating:

| Cloud | How it signs in |
|-------|-----------------|
| AWS | Access keys or an assumed role |
| Azure | Service principal (tenant ID, client ID, secret or certificate) |
| GCP | Application default credentials or a service account key |
| Kubernetes | A kubeconfig |

Use an identity with **read-only** permissions. Ready-made policies are in
[`docs/iam-policies/`](docs/iam-policies/), and Terraform/CloudFormation templates are in
[`docs/deployment/`](docs/deployment/).

### 3. Build a Collection Kit in Acquire

Go to **Configuration → Acquire**:

1. Pick the cloud.
2. Add the log sources you want from the artifact library (CloudTrail, sign-in logs, flow logs,
   and so on; see [`docs/collectors.md`](docs/collectors.md) for the full list).
3. Give the kit a name and set the time window (**Since** / **Until**).
4. Click **Save kit**.

The kit now appears under **Collection Kits**.

### 4. Run the kit

Go to **Collection Kits** and pick one of the two ways to run it.

**Option A: run it from the console** (AWS, Azure, GCP)

Click **Run**, choose a new or existing case, and choose the connection to use. The console
shows live progress, and the evidence is imported into the case automatically when the run
finishes.

**Option B: run it from a terminal** (all clouds; the only option for Kubernetes)

Click **Download Kit** and choose the connection to embed. You get a `.kit` file. Copy it to
the machine that should do the collection (your workstation, a cloud shell, or a Kubernetes
control-plane node) and run:

```bash
ventra run my-kit.kit
```

This collects everything the kit lists and writes a sealed evidence package to `./evidence`
(change it with `--out`). Bring the `.tar.zst` package back to your workstation and import it
in the console with **Cases → Import package**.

> **A `.kit` file contains working credentials.** Treat it like a password: don't email it,
> don't commit it, and delete it when the collection is done. Kits expire, and `ventra run`
> refuses to run an expired kit.

On a Kubernetes node, `ventra run` re-runs itself with `sudo` so it can read root-only log
files. Pass `--no-sudo` to skip that; those sources are then recorded as gaps.

To run a kit in **AWS CloudShell**, upload the `.kit` file, then install Ventra and run it:

```bash
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
ventra run my-kit.kit
```

### 5. Investigate

Open the case under **Cases**. The panels follow the case's cloud:

| Panel | What you see |
|-------|--------------|
| **Timeline** | Control-plane activity: CloudTrail, Azure Activity Log and Entra, GCP Cloud Audit Logs |
| **Security Findings** | GuardDuty, Security Hub, Inspector, Macie, Defender for Cloud, Security Command Center |
| **Identity & Access** | Users, roles, policies, RBAC, keys and secrets inventory |
| **Network Activity** | Flow logs, firewall logs, egress and rejected connections |
| **Web & DNS** | Load balancer, CDN, WAF and DNS query logs |
| **Kubernetes Audit** | EKS, AKS, GKE and on-prem API-server audit logs |
| **Data Access** | S3, Storage, Key Vault, GCS, BigQuery, Cloud SQL and Secret Manager access |
| **Logs Coverage** | What was collected, and which sources were disabled, empty or denied |
| **Resource Inventory** | Compute, storage and serverless inventory snapshots |
| **Raw Evidence** | The original sealed files from the package |

**Gaps count as evidence.** If a log source was turned off or access was denied, Ventra records
that in the package instead of silently skipping it.

To send a case to a SIEM, use **Export** in the console (Elastic NDJSON), or see
[`ingester/pipelines/elastic/`](ingester/pipelines/elastic/README.md).

---

## Try it with demo data

You can explore the console without a cloud account by using a synthetic demo case:

```bash
git clone https://github.com/Haggag-22/Ventra.git
cd Ventra
uv run python tests/fixtures/generate_demo_case.py --out ~/ventra-demo
cd ~
ventra gui
```

Then go to **Cases → Import package** and pick the `.tar.zst` file in `~/ventra-demo`. The demo
is a made-up AWS intrusion (leaked key, privilege escalation, CloudTrail tampering, data
exfiltration). Azure, GCP and Kubernetes generators live next to it in `tests/fixtures/`.

---

## Commands

| Command | What it does |
|---------|--------------|
| `ventra gui` | Open the console (`--no-open` to skip opening a browser tab) |
| `ventra run <kit>.kit` | Run a Collection Kit downloaded from Acquire (`--out`, `--no-sudo`) |
| `ventra import <path>` | Import a package from a terminal into the console's case store (`--case-store <dir>` to use another one) |
| `ventra-verify <package>` | Check a package's hashes and seal without importing it |
| `ventra-export --case-dir <dir> --out <dir>` | Export a case's events as Elastic NDJSON |
| `ventra artifacts list` | List every log source Ventra can collect (`--cloud aws`) |
| `ventra --help` | All commands and options |

The console keeps its data (cases, saved kits, connections) in
`~/Library/Application Support/Ventra` on macOS and `~/.ventra` on Linux. Set `VENTRA_HOME` to
use another folder.

---

## Update and uninstall

```bash
uv tool upgrade ventra       # update to the latest release
uv tool uninstall ventra     # remove Ventra
```

With pipx: `pipx upgrade ventra` / `pipx uninstall ventra`. Uninstalling does not delete your
cases; remove the data folder above if you want them gone.

---

## Security and privacy

- **Read-only collection.** Collectors only call list, get and read APIs. CI checks this on
  every change.
- **Tamper-evident packages.** Every file is SHA-256 hashed when it is collected, and the
  package manifest is sealed. `ventra-verify` re-checks it.
- **Local only.** The console listens on `127.0.0.1`, rejects requests addressed to other host
  names, makes no outbound calls, and has no telemetry. To serve it under another host name
  (for example behind your own proxy), list that name in `VENTRA_ALLOWED_HOSTS`.
- **Saved credentials stay private.** Connections are stored with owner-only file permissions
  and are masked in the console.

Found a vulnerability? Please report it privately; see [SECURITY.md](SECURITY.md).

---

## What Ventra is not

- **Not a SIEM:** a case is one scoped investigation, not an always-on log pipeline.
- **Not EDR or disk forensics:** memory, disk images and OS internals stay with dedicated tools.
- **Not a containment tool:** it never isolates, modifies or deletes resources.
- **Not long-term storage:** retention of evidence packages is up to your team.

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/collectors.md`](docs/collectors.md) | Every collector, per cloud |
| [`docs/runbooks/operator.md`](docs/runbooks/operator.md) | Running a collection |
| [`docs/runbooks/analyst.md`](docs/runbooks/analyst.md) | Investigating a case |
| [`docs/runbooks/data-custodian.md`](docs/runbooks/data-custodian.md) | Receiving, storing and deleting evidence |
| [`docs/architecture.md`](docs/architecture.md) | How the collector, ingester and console fit together |
| [`docs/evidence-package-format.md`](docs/evidence-package-format.md) | The evidence package format |
| [`docs/artifacts.md`](docs/artifacts.md) | The artifact catalog and packs |
| [`docs/iam-policies/`](docs/iam-policies/) | Read-only permissions per cloud |
| [`docs/threat-coverage.md`](docs/threat-coverage.md) | Which log sources cover which attacker techniques |

---

## Contributing

```bash
git clone https://github.com/Haggag-22/Ventra.git
cd Ventra
uv sync          # creates .venv with all dependencies and dev tools
uv run pytest    # run the test suite
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache-2.0](LICENSE).
