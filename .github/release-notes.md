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

The PyPI package ships the **collector only**. The investigation console runs from a source
clone on your IR workstation:

```bash
git clone https://github.com/Haggag-22/Ventra.git
cd Ventra
make install && ventra gui
```

Import the sealed package from the Cases screen, or run `ventra-ingest` after installing
[`ventra-ingester`](https://github.com/Haggag-22/Ventra/tree/main/ingester) from the repo.

---

## What's included

- Read-only AWS, Azure, and GCP collectors (`ventra collect aws|azure|gcp`)
- Sealed evidence packages (EPF manifest + SHA-256 per source)
- Does **not** include the Next.js console frontend (clone the repo for `ventra gui`)

More: [Operator runbook](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/operator.md) · [Analyst runbook](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/analyst.md)
