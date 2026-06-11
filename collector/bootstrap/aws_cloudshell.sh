#!/usr/bin/env bash
# Harbor collector bootstrap for AWS CloudShell.
#
# Paste this into CloudShell. It installs the collector into a user-local venv (CloudShell's
# home is writable and persists within a session) and runs a baseline collection.
#
# Review before running anything: this script only *reads* — it installs the collector and
# invokes it under your existing CloudShell credentials. The collector's IAM requirements are
# published at docs/iam-policies/aws-collector-readonly.json.
set -euo pipefail

CASE_ID="${HARBOR_CASE:-CASE-$(date +%Y%m%d-%H%M%S)}"
PROFILE="${HARBOR_PROFILE:-baseline}"
OUT_DIR="${HARBOR_OUT:-$HOME/harbor-evidence}"
SINCE="${HARBOR_SINCE:-}"
REGIONS="${HARBOR_REGIONS:-}"

echo "⚓ Harbor collector — case=${CASE_ID} profile=${PROFILE}"

# 1. Isolated venv so we don't disturb CloudShell's system Python.
python3 -m venv "$HOME/.harbor-venv"
# shellcheck disable=SC1091
source "$HOME/.harbor-venv/bin/activate"
pip install --quiet --upgrade pip

# 2. Install the collector. Pin to a released, signed wheel in production; this uses PyPI.
pip install --quiet "harbor-collector[zstd]"

# 3. Run.
ARGS=(aws --case "$CASE_ID" --profile "$PROFILE" --out "$OUT_DIR")
[ -n "$SINCE" ]   && ARGS+=(--since "$SINCE")
[ -n "$REGIONS" ] && ARGS+=(--regions "$REGIONS")

harbor-collect "${ARGS[@]}"

echo
echo "Done. Evidence package(s) in: ${OUT_DIR}"
echo "Verify the printed SHA-256 matches what the IR team receives."
