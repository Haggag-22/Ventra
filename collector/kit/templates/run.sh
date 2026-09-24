#!/usr/bin/env bash
# Thin wrapper — prefer: python3 ventra.py [options]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$ROOT/ventra.py" "$@"
