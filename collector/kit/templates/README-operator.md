# Ventra Acquisition Kit

This zip contains a minimal operator bundle for read-only cloud evidence collection.

## Contents

- `acquisition.yaml` — case metadata, global filters, and selected artifacts (with parameters)
- `artifacts/` — YAML artifact definitions included in this run
- `iam/` — merged read-only IAM policy references (when applicable)
- `dist/` — bundled `ventra` wheel when available (otherwise see `INSTALL.md`)
- `requirements.txt` — runtime dependencies for bootstrap
- `ventra.py` — Python entry point (recommended)
- `run.sh` — thin wrapper that calls `ventra.py`

## Usage

Case ID, cloud, artifacts, and time window come from `acquisition.yaml` — you do not pass the case name on the command line.

```bash
python3 ventra.py --out ./ventra-evidence
```

Or with the shell wrapper:

```bash
chmod +x run.sh ventra.py
./run.sh --out ./ventra-evidence
```

### Cloud credentials / scope

| Cloud | Flag | What it does |
|-------|------|----------------|
| **AWS** | `--profile NAME` | Named profile from `~/.aws/credentials` (same as `AWS_PROFILE`) |
| **Azure** | `--subscription ID` | Subscription id(s), comma-separated (same as `AZURE_SUBSCRIPTION_ID`) |
| **GCP** | `--project ID` | Project id(s), comma-separated (`acquisition.yaml`, `GOOGLE_CLOUD_PROJECT`) |
| **GCP** | `--credentials PATH` | Service account JSON key (`GOOGLE_APPLICATION_CREDENTIALS`) |

| Flag | What it does |
|------|----------------|
| `--out DIR` | Where to write the sealed `.tar.zst` package (default: `./ventra-evidence`) |

```bash
# AWS
python3 ventra.py --profile ir-readonly --out ./ventra-evidence

# Azure (subscription can also live in acquisition.yaml)
python3 ventra.py --out ./evidence

# GCP (project can also live in acquisition.yaml)
python3 ventra.py --project my-gcp-project --credentials /secure/ventra-sa.json --out ./evidence
```

Set `VENTRA_CLOUD` to `aws`, `azure`, or `gcp` before running if you need to override the
cloud named in `acquisition.yaml`.

The client machine needs network access for `pip install` and cloud API credentials with the
permissions in `iam/` for the selected artifacts only.

### GCP — before you run

1. **Create a dedicated collector service account** in the client org (e.g. `ventra-collector@...`).
2. **Grant the read-only role** from `iam/gcp-collector-readonly.json` on every in-scope project (or at folder/org scope).
3. **Generate a JSON key** for that service account (or run on Cloud Shell / GCE with the SA attached and skip the key).
4. **Set scope and credentials before running** (never put secrets in the zip):

```bash
python3 ventra.py \
  --project proj-a,proj-b \
  --credentials /secure/ventra-sa.json \
  --out ./evidence
```

`acquisition.yaml` may include `project` (comma-separated). The service account key stays on
disk outside the kit — use `--credentials` or `GOOGLE_APPLICATION_CREDENTIALS`.

See `docs/gcp-authentication.md` in the Ventra repository for full scenarios.

### Azure — before you run

1. **Create / use an Entra app registration** (service principal) for collection.
2. **Grant admin consent** for Microsoft Graph application permissions listed in `iam/azure-collector-graph.json` (or the merged policy in `iam/`).
3. **Assign ARM read access on each in-scope subscription** using the custom role in `iam/azure-collector-readonly.json` (or **Reader** as a minimum). Without this, activity log, RBAC, flow logs, and network collectors return `AuthorizationFailed`.
4. **Add Storage Blob Data Reader** on storage accounts that hold flow logs and storage diagnostics (or at subscription scope).
5. **Set credentials before running** (never put secrets in the zip):

```bash
export AZURE_CLIENT_SECRET='<app-secret>'
# Optional if not already in acquisition.yaml:
export AZURE_TENANT_ID='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
export AZURE_CLIENT_ID='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
export AZURE_SUBSCRIPTION_ID='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
python3 ventra.py --out ./evidence
```

`acquisition.yaml` may include `subscription`, `azure_tenant_id`, and `azure_client_id`. The client secret or certificate password stays in environment variables only.

**Expected gaps on trial / student tenants:** Entra sign-in logs need Entra ID P1/P2; M365 Unified Audit needs extra Graph/M365 permissions; Front Door / Firewall / AKS collectors gap when those resources are not deployed.

**After downloading a new kit:** delete the `.venv` folder in the kit directory so `ventra.py` reinstalls updated dependencies:

```bash
rm -rf .venv
python3 ventra.py --out ./evidence
```

### Bundled ventra wheel (`dist/`)

Every kit from Acquire includes `dist/ventra-*.whl` — the Ventra Python package pinned to
`ventra_version` in `acquisition.yaml`.

When the IR lead builds from a **Ventra source checkout** (`ventra gui`), the wheel is built
fresh from that working tree (unreleased changes included). When built outside a clone, the
console downloads `ventra==ventra_version` from **PyPI** instead.

Install the wheel in the kit venv so collection works **without downloading from the public
internet (PyPI)** at run time:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install dist/ventra-*.whl   # offline — no PyPI needed for ventra itself
python3 ventra.py --out ./ventra-evidence
```

| | With wheel in `dist/` | Without wheel (not used for Acquire kits) |
|---|----------------------|----------------------------------------|
| **Best for** | Air-gapped hosts, strict egress, reproducible version | N/A — Acquire always bundles the wheel |
| **Tradeoff** | Slightly larger zip | — |
| **Version** | Matches `ventra_version` in `acquisition.yaml` (from PyPI) | — |

If `dist/` is empty, the kit build failed — rebuild from a machine with PyPI access and an
installed Ventra release matching what you published.
