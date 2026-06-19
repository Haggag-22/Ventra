# Ventra Acquisition Kit

This zip contains a minimal operator bundle for read-only cloud evidence collection.

## Contents

- `acquisition.yaml` — case metadata and selected artifact list
- `artifacts/` — YAML artifact definitions included in this run
- `iam/` — merged read-only IAM policy references (when applicable)
- `run.sh` — thin wrapper around `ventra collect`

## Usage

```bash
chmod +x run.sh
./run.sh CASE-2026-0042 ./ventra-evidence
```

Set `VENTRA_CLOUD` to `aws`, `azure`, or `gcp` before running if the kit targets a specific cloud.
