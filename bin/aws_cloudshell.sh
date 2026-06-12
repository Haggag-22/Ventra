#!/usr/bin/env bash
# Ventra one-shot bootstrap for AWS CloudShell: install (if needed) + run a collection.
#
# For install-only (recommended for repeat use), run bin/install-cloudshell.sh instead,
# then use ``ventra collect aws`` directly on every subsequent session.
#
# Review before running: read-only collection under your CloudShell credentials.
# IAM policy: docs/iam-policies/aws-collector-readonly.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CASE_ID="${VENTRA_CASE:-CASE-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${VENTRA_OUT:-$HOME/ventra-evidence}"
SINCE="${VENTRA_SINCE:-}"
REGIONS="${VENTRA_REGIONS:-}"

VENTRA_INSTALL_SOURCED=1
# shellcheck source=install-cloudshell.sh
source "${SCRIPT_DIR}/install-cloudshell.sh"
main

echo
echo "⚓ Ventra collection — case=${CASE_ID}"

ARGS=(collect aws --case "$CASE_ID" --out "$OUT_DIR" --no-ingest)
[ -n "$SINCE" ]   && ARGS+=(--since "$SINCE")
[ -n "$REGIONS" ] && ARGS+=(--regions "$REGIONS")

ventra "${ARGS[@]}"

echo
echo "Done. Evidence package(s) in: ${OUT_DIR}"
echo "Verify the printed SHA-256 matches what the IR team receives."
