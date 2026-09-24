#!/usr/bin/env bash
# Build a static Next.js export for bundling into the ventra wheel.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND="$ROOT/console/frontend"
cd "$FRONTEND"
if [[ ! -d node_modules ]]; then
  npm ci --no-audit --no-fund
fi
rm -rf out .next
export VENTRA_STATIC_EXPORT=1
npm run build
test -f out/index.html
echo "Static console ready: $FRONTEND/out"
