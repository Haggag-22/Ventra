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
| **GCP** | `--project ID` | Project id(s), comma-separated (same as `GOOGLE_CLOUD_PROJECT`) |

| Flag | What it does |
|------|----------------|
| `--out DIR` | Where to write the sealed `.tar.zst` package (default: `./ventra-evidence`) |

Azure and GCP do not use a “profile” name like AWS. Azure auth comes from `az login` or a service principal in env vars; GCP auth comes from Application Default Credentials (`gcloud auth application-default login`) or `GOOGLE_APPLICATION_CREDENTIALS`.

```bash
# AWS
python3 ventra.py --profile ir-readonly --out ./ventra-evidence

# Azure
python3 ventra.py --subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# GCP
python3 ventra.py --project my-gcp-project --out ./evidence
```

Set `VENTRA_CLOUD` to `aws`, `azure`, or `gcp` before running if you need to override the
cloud named in `acquisition.yaml`.

The client machine needs network access for `pip install` and cloud API credentials with the
permissions in `iam/` for the selected artifacts only.
