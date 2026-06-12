#!/usr/bin/env bash
# Harbor one-shot bootstrap for AWS CloudShell: install (if needed) + run a collection.
#
# For install-only (recommended for repeat use), run bin/install-cloudshell.sh instead,
# then use ``harbor collect aws`` directly on every subsequent session.
#
# Review before running: read-only collection under your CloudShell credentials.
# IAM policy: docs/iam-policies/aws-collector-readonly.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CASE_ID="${HARBOR_CASE:-CASE-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${HARBOR_OUT:-$HOME/harbor-evidence}"
SINCE="${HARBOR_SINCE:-}"
REGIONS="${HARBOR_REGIONS:-}"

HARBOR_INSTALL_SOURCED=1
# shellcheck source=install-cloudshell.sh
source "${SCRIPT_DIR}/install-cloudshell.sh"
main

echo
echo "⚓ Harbor collection — case=${CASE_ID}"

ARGS=(collect aws --case "$CASE_ID" --out "$OUT_DIR")
[ -n "$SINCE" ]   && ARGS+=(--since "$SINCE")
[ -n "$REGIONS" ] && ARGS+=(--regions "$REGIONS")

harbor "${ARGS[@]}"

echo
echo "Done. Evidence package(s) in: ${OUT_DIR}"
echo "Verify the printed SHA-256 matches what the IR team receives."
