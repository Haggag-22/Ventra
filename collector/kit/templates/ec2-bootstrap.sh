#!/usr/bin/env bash
# Bootstrap Python venv for Ventra kit on Amazon Linux / Ubuntu EC2.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

if compgen -G "dist/ventra-*.whl" >/dev/null; then
  pip install -q dist/ventra-*.whl
else
  echo "warning: no bundled wheel in dist/ — run pip install ventra when online" >&2
fi

echo "Bootstrap complete. Run: ./run.sh --out /opt/ventra-evidence"
