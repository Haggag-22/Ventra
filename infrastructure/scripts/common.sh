#!/usr/bin/env bash
# Shared helpers for Ventra collector lab traffic generation.
set -euo pipefail

VENTRA_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENTRA_INFRA_ROOT="$(cd "${VENTRA_SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ITERATIONS="${ITERATIONS:-3}"
DRY_RUN="${DRY_RUN:-0}"
PAUSE_SECS="${PAUSE_SECS:-1}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -n, --iterations N   Repeat each traffic pattern N times (default: ${ITERATIONS})
  -d, --dry-run        Print actions without executing
  -p, --pause SECS     Pause between iterations (default: ${PAUSE_SECS})
  -h, --help           Show this help

Environment:
  ITERATIONS, DRY_RUN, PAUSE_SECS
EOF
}

parse_common_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--iterations) ITERATIONS="$2"; shift 2 ;;
      -d|--dry-run) DRY_RUN=1; shift ;;
      -p|--pause) PAUSE_SECS="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) break ;;
    esac
  done
  export ITERATIONS DRY_RUN PAUSE_SECS
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${RED}Missing required command: ${cmd}${NC}" >&2
    exit 1
  fi
}

section() {
  echo -e "\n${BLUE}==> $*${NC}"
}

ok()   { echo -e "${GREEN}  ok${NC} $*"; }
warn() { echo -e "${YELLOW}  warn${NC} $*"; }
fail() { echo -e "${RED}  fail${NC} $*"; }

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "  [dry-run] $*"
    return 0
  fi
  "$@"
}

load_tf_json() {
  local cloud_dir="$1"
  local out_var="$2"
  if [[ ! -d "$cloud_dir" ]]; then
    echo -e "${RED}Terraform dir not found: ${cloud_dir}${NC}" >&2
    exit 1
  fi
  if ! command -v terraform >/dev/null 2>&1; then
    echo -e "${RED}terraform required to read outputs from ${cloud_dir}${NC}" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}jq required to parse terraform outputs${NC}" >&2
    exit 1
  fi
  local json
  json="$(terraform -chdir="$cloud_dir" output -json 2>/dev/null || true)"
  if [[ -z "$json" || "$json" == "{}" ]]; then
    echo -e "${RED}No terraform outputs in ${cloud_dir}. Run terraform apply first.${NC}" >&2
    exit 1
  fi
  printf -v "$out_var" '%s' "$json"
}

tf_out() {
  local json="$1"
  local key="$2"
  jq -r ".${key}.value // empty" <<<"$json"
}

retry_http() {
  local url="$1"
  local label="${2:-GET $url}"
  local i code
  for ((i = 1; i <= 3; i++)); do
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "  [dry-run] curl -fsS -o /dev/null -w '%{http_code}' '$url'"
      return 0
    fi
    code="$(curl -fsS -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 30 "$url" 2>/dev/null || echo "000")"
    if [[ "$code" =~ ^[23] ]]; then
      ok "$label → HTTP $code"
      return 0
    fi
    warn "$label attempt $i → HTTP $code"
    sleep 1
  done
  fail "$label (gave up after 3 tries)"
  return 1
}

pause_between() {
  if [[ "$DRY_RUN" != "1" && "$PAUSE_SECS" != "0" ]]; then
    sleep "$PAUSE_SECS"
  fi
}

summary_box() {
  local cloud="$1"
  shift
  echo -e "\n${GREEN}=== ${cloud} traffic generation complete ===${NC}"
  while [[ $# -gt 0 ]]; do
    echo "  • $1"
    shift
  done
  echo -e "${YELLOW}Wait 15–60 minutes for logs to land, then run your Acquire kit.${NC}"
}
