#!/usr/bin/env bash
# Verify a Harbor release artifact before running it in a client environment.
set -euo pipefail

ARTIFACT="${1:?usage: verify_signature.sh <artifact> [pubkey]}"
PUBKEY="${2:-harbor-release.pub}"

if command -v cosign >/dev/null 2>&1; then
  cosign verify-blob --key "$PUBKEY" --signature "${ARTIFACT}.sig" "$ARTIFACT"
  echo "OK: cosign signature valid for ${ARTIFACT}"
elif command -v minisign >/dev/null 2>&1; then
  minisign -V -p "$PUBKEY" -m "$ARTIFACT"
  echo "OK: minisign signature valid for ${ARTIFACT}"
else
  echo "Neither cosign nor minisign found; falling back to SHA-256 check." >&2
  shasum -a 256 -c "${ARTIFACT}.sha256"
fi
