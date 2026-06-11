#!/usr/bin/env bash
# Ensure activated .venv never writes __pycache__ under the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKER="# harbor: no bytecode"
ACTIVATE="$ROOT/.venv/bin/activate"

if [[ ! -f "$ACTIVATE" ]]; then
  exit 0
fi

if ! grep -qF "$MARKER" "$ACTIVATE"; then
  cat >>"$ACTIVATE" <<'EOF'

# harbor: no bytecode
export PYTHONDONTWRITEBYTECODE=1
EOF
fi
