#!/usr/bin/env bash
# Remove Python bytecode caches under the repo (safe to delete; not source).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

while IFS= read -r -d '' dir; do
  rm -rf "$dir"
done < <(find "$ROOT" -type d \( -name __pycache__ -o -name .pytest_cache \) ! -path '*/.venv/*' -print0 2>/dev/null)

find "$ROOT" -type f \( -name '*.pyc' -o -name '*.pyo' \) ! -path '*/.venv/*' -delete 2>/dev/null || true
