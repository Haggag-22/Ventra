#!/usr/bin/env bash
# Ensure activated .venv never writes __pycache__ under the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKER="# ventra: no bytecode"
ACTIVATE="$ROOT/.venv/bin/activate"

if [[ ! -f "$ACTIVATE" ]]; then
  exit 0
fi

if ! grep -qF "$MARKER" "$ACTIVATE"; then
  cat >>"$ACTIVATE" <<'EOF'

# ventra: no bytecode
export PYTHONDONTWRITEBYTECODE=1
EOF
fi
