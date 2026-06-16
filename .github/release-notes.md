## Install

This release is published to PyPI as **`ventra==@VERSION@`**.

### AWS CloudShell (recommended)

Review the read-only IAM policy in the repo first:
[`docs/iam-policies/aws-collector-readonly.json`](https://github.com/Haggag-22/Ventra/blob/main/docs/iam-policies/aws-collector-readonly.json)

```bash
# Installer — creates ~/.ventra-venv, pip-installs from PyPI, adds ventra to PATH
curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh | bash

# Pin this release:
VENTRA_INSTALL_SPEC='ventra==@VERSION@' \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/Haggag-22/Ventra/main/bin/install-cloudshell.sh)"
```

### pip (any environment with Python 3.11+)

```bash
python3 -m venv ~/.ventra-venv
source ~/.ventra-venv/bin/activate
pip install --upgrade pip
pip install ventra==@VERSION@

ventra --version
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
ventra gui
```

Import the sealed package from the Cases screen, or run `ventra-ingest` after installing
[`ventra-ingester`](https://github.com/Haggag-22/Ventra/tree/main/ingester) from the repo.

---

## What's included

- Read-only AWS collector (`ventra collect aws`)
- Sealed evidence packages (EPF manifest + SHA-256 per source)
- Does **not** include the Next.js console frontend (clone the repo for `ventra gui`)

More: [Operator runbook](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/operator.md) · [Analyst runbook](https://github.com/Haggag-22/Ventra/blob/main/docs/runbooks/analyst.md)
