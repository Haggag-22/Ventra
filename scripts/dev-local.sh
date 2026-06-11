#!/usr/bin/env bash
# Local dev: backend (uvicorn --reload) + frontend (next dev).
# Open http://localhost:8080 — API is proxied to :8000.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p cases .harbor-uploads

if [[ -x "$ROOT/.venv/bin/uvicorn" ]]; then
  UVICORN="$ROOT/.venv/bin/uvicorn"
  NPM="npm"
elif command -v uvicorn >/dev/null 2>&1; then
  UVICORN="uvicorn"
  NPM="npm"
else
  echo "error: uvicorn not found. Run: make dev-setup" >&2
  exit 1
fi

export HARBOR_CASE_STORE="$ROOT/cases"
export HARBOR_UPLOAD_DIR="$ROOT/.harbor-uploads"

FRONTEND_PORT=8080
if lsof -i :8080 -sTCP:LISTEN >/dev/null 2>&1; then
  FRONTEND_PORT=8081
fi

echo "Harbor local dev"
echo "  Frontend: http://localhost:${FRONTEND_PORT}"
echo "  Backend:  http://127.0.0.1:8000"
echo "  Cases:    $HARBOR_CASE_STORE"
if [[ "$FRONTEND_PORT" != "8080" ]]; then
  echo "  Note: port 8080 is in use — frontend on :8081"
fi
echo ""

cleanup() {
  kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$UVICORN" app.main:app --reload --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

sleep 1

cd "$ROOT/console/frontend"
"$NPM" run dev -- -p "$FRONTEND_PORT" &
FRONTEND_PID=$!

wait "$BACKEND_PID" "$FRONTEND_PID"
