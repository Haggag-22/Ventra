## Install

This release is published to PyPI as **`ventra==@VERSION@`**.

### macOS / Linux (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install.sh | bash
ventra --version
```

Pin this release:

```bash
VENTRA_INSTALL_SPEC='ventra==@VERSION@' \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install.sh)"
```

Install from a local wheel:

```bash
uv tool install --force ./ventra-@VERSION@-py3-none-any.whl
```

### AWS CloudShell

Review the read-only IAM policy first:
[`docs/iam-policies/aws-collector-readonly.json`](https://github.com/Haggag-22/Ventra/blob/main/docs/iam-policies/aws-collector-readonly.json)

```bash
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash
```

### Collect evidence

```bash
ventra collect aws \
  --case CASE-2026-0042 \
  --since 2026-05-01 \
  --out ~/ventra-evidence
```

List collectors: `ventra collect aws --list-collectors`

### Analyst console

```bash
ventra gui
```

Opens the bundled investigation UI (same PyPI install). Import a sealed package from the Cases
screen, or run `ventra import` / `ventra-ingest`.

---

## What's included

- Read-only AWS, Azure, and GCP collectors (`ventra collect aws|azure|gcp`)
- Sealed evidence packages (EPF manifest + SHA-256 per source)
- Does **not** include the Next.js console frontend (clone the repo for `ventra gui`)

More: [Operator runbook](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/operator.md) · [Analyst runbook](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/analyst.md)
