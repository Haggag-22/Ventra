#!/usr/bin/env bash
# Bootstrap Python venv for Ventra kit on Amazon Linux / Ubuntu EC2 (uv, not pip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:${PATH:-}"
fi

uv venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
uv pip install -q -r requirements.txt

if compgen -G "dist/ventra-*.whl" >/dev/null; then
  uv pip install -q --reinstall --no-deps dist/ventra-*.whl
else
  echo "warning: no bundled wheel in dist/ — run: uv tool install ventra" >&2
fi

echo "Bootstrap complete. Run: ./run.sh --out /opt/ventra-evidence"
