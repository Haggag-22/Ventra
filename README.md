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
[`docs/iam-policies/`](https://github.com/Haggag-22/Ventra/blob/main/docs/iam-policies/), and Terraform/CloudFormation templates are in
[`docs/deployment/`](https://github.com/Haggag-22/Ventra/blob/main/docs/deployment/).

![Saved cloud connections on the Authentication page](https://raw.githubusercontent.com/Haggag-22/Ventra/main/docs/screenshots/Auth%20Sample.png)

### 3. Build a Collection Kit in Acquire

Go to **Configuration → Acquire**:

1. Pick the cloud.
2. Add the log sources you want from the artifact library (CloudTrail, sign-in logs, flow logs,
   and so on; see [`docs/collectors.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/collectors.md) for the full list).
3. Give the kit a name and set the time window (**Since** / **Until**).
4. Click **Save kit**.

The kit now appears under **Collection Kits**.

![Building a kit in Acquire](https://raw.githubusercontent.com/Haggag-22/Ventra/main/docs/screenshots/Acquire%20Sample.png)

### 4. Run the kit

Go to **Collection Kits** and pick one of the two ways to run it.

![Saved kits, with Run and Download Kit](https://raw.githubusercontent.com/Haggag-22/Ventra/main/docs/screenshots/Collection%20Kit%20Sample.png)

**Option A: run it from the console** (AWS, Azure, GCP)

Click **Run**, choose a new or existing case, and choose the connection to use. The console
shows live progress, and the evidence is imported into the case automatically when the run
finishes.

![A collection in progress on Scans](https://raw.githubusercontent.com/Haggag-22/Ventra/main/docs/screenshots/Running%20Scan%20Sample.png)

**Option B: run it from a terminal** (all clouds; the only option for Kubernetes)

Click **Download Kit** and choose the connection to embed. You get a `.kit` file. Copy it to
the machine that should do the collection (your workstation, a cloud shell, or a Kubernetes
control-plane node) and run:

```bash
ventra run my-kit.kit --out ./evidence
```

This collects everything the kit lists and writes a sealed evidence package to the `--out`
folder. Leave `--out` off in a terminal and Ventra asks for the folder; scripts and other
non-interactive runs must pass it. Bring the `.tar.zst` package back to your workstation and
import it in the console with **Cases → Import package**.

> **A `.kit` file contains working credentials.** Treat it like a password: don't email it,
> don't commit it, and delete it when the collection is done. Kits expire, and `ventra run`
> refuses to run an expired kit.

A kit stays runnable for up to **7 days**, or until its embedded cloud credential expires if
that comes first. `ventra run` prints the real expiry and says when the credential, not the
7-day limit, is what ends it. What each cloud allows:

| Cloud | Embedded credential | Kit runnable for |
|-------|---------------------|------------------|
| AWS, access keys | STS session token | 36 hours (1 hour for the root user) |
| AWS, role | STS AssumeRole session | the role's maximum session, at most 12 hours (1 hour when chaining roles) |
| GCP, service account | OAuth access token | 1 hour; 12 hours if the org policy `iam.allowServiceAccountCredentialLifetimeExtension` lists the account |
| Azure, service principal | Resource Manager access token | 60–90 minutes (set by Microsoft Entra ID) |
| Kubernetes, ServiceAccount token | the token in the kubeconfig | the token's own expiry, up to 7 days (`kubectl create token <sa> --duration=168h`) |
| AWS profile / GCP ADC / kubeconfig auth plugin | none (uses the run host's login) | 7 days |

Ventra never stretches a kit with a long-lived secret. If no short-lived credential can be
minted and the kit has to carry one (an access key, service account key, client secret or
certificate, or a token without an expiry), the kit is limited to 4 hours.

On a Kubernetes node, `ventra run` re-runs itself with `sudo` so it can read root-only log
files. Pass `--no-sudo` to skip that; those sources are then recorded as gaps.

To run a kit in **AWS CloudShell**, upload the `.kit` file, then install Ventra and run it:

```bash
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
ventra run my-kit.kit --out ./evidence
```

### 5. Investigate

Open the case under **Cases**. The panels follow the case's cloud:

![Imported cases](https://raw.githubusercontent.com/Haggag-22/Ventra/main/docs/screenshots/Cases%20Sample.png)

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
[`ingester/pipelines/elastic/`](https://github.com/Haggag-22/Ventra/blob/main/ingester/pipelines/elastic/README.md).

![Exporting a case](https://raw.githubusercontent.com/Haggag-22/Ventra/main/docs/screenshots/Export%20Sample.png)

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
| `ventra run <kit>.kit --out <folder>` | Run a Collection Kit downloaded from Acquire (`--no-sudo` to skip the sudo re-run) |
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

Found a vulnerability? Please report it privately; see [SECURITY.md](https://github.com/Haggag-22/Ventra/blob/main/SECURITY.md).

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
| [`docs/collectors.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/collectors.md) | Every collector, per cloud |
| [`docs/runbooks/operator.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/operator.md) | Running a collection |
| [`docs/runbooks/analyst.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/analyst.md) | Investigating a case |
| [`docs/runbooks/data-custodian.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/data-custodian.md) | Receiving, storing and deleting evidence |
| [`docs/architecture.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/architecture.md) | How the collector, ingester and console fit together |
| [`docs/evidence-package-format.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/evidence-package-format.md) | The evidence package format |
| [`docs/artifacts.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/artifacts.md) | The artifact catalog and packs |
| [`docs/iam-policies/`](https://github.com/Haggag-22/Ventra/blob/main/docs/iam-policies/) | Read-only permissions per cloud |
| [`docs/threat-coverage.md`](https://github.com/Haggag-22/Ventra/blob/main/docs/threat-coverage.md) | Which log sources cover which attacker techniques |

---

## Contributing

```bash
git clone https://github.com/Haggag-22/Ventra.git
cd Ventra
uv sync          # creates .venv with all dependencies and dev tools
uv run pytest    # run the test suite
```

See [CONTRIBUTING.md](https://github.com/Haggag-22/Ventra/blob/main/CONTRIBUTING.md) for the development setup, and
[CODE_OF_CONDUCT.md](https://github.com/Haggag-22/Ventra/blob/main/CODE_OF_CONDUCT.md). Changes are listed in [CHANGELOG.md](https://github.com/Haggag-22/Ventra/blob/main/CHANGELOG.md).

## License

[Apache-2.0](https://github.com/Haggag-22/Ventra/blob/main/LICENSE).
