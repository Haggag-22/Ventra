#!/usr/bin/env bash
# Run all Ventra lab traffic generators (AWS, Azure, GCP).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

CLOUDS=(aws azure gcp)
FAILED=()

parse_common_args "$@"

echo -e "${GREEN}Ventra multi-cloud traffic generator${NC}"
echo "  iterations=${ITERATIONS}  dry_run=${DRY_RUN}"
echo

for cloud in "${CLOUDS[@]}"; do
  script="${SCRIPT_DIR}/${cloud}/generate.sh"
  if [[ ! -x "$script" ]]; then
    warn "skip ${cloud}: ${script} not found"
    continue
  fi
  section "Running ${cloud}"
  if bash "$script" -n "$ITERATIONS" ${DRY_RUN:+--dry-run} -p "$PAUSE_SECS"; then
    ok "${cloud} complete"
  else
    fail "${cloud} failed"
    FAILED+=("$cloud")
  fi
done

echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
  echo -e "${GREEN}All clouds complete.${NC} Wait 15–60 minutes, then run Acquire kits."
else
  echo -e "${YELLOW}Finished with failures: ${FAILED[*]}${NC}"
  exit 1
fi
