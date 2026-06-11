#!/usr/bin/env bash
# Install lightweight git hooks that prune __pycache__ after checkout/merge.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS_DIR="$ROOT/.git/hooks"

if [[ ! -d "$HOOKS_DIR" ]]; then
  echo "skip: not a git repo — git hooks not installed" >&2
  exit 0
fi

install_hook() {
  local name="$1"
  local path="$HOOKS_DIR/$name"
  cat >"$path" <<EOF
#!/bin/sh
# Harbor: drop Python bytecode caches after git updates.
"$ROOT/scripts/clean-pycache.sh" >/dev/null 2>&1 || true
EOF
  chmod +x "$path"
}

install_hook post-checkout
install_hook post-merge

echo "Installed git hooks: post-checkout, post-merge (clean __pycache__)"
