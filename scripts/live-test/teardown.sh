#!/usr/bin/env bash
# Reverse run-test.sh: clean up Stratus, disable the detection services THIS harness enabled,
# and destroy the Terraform infrastructure. Safe to run repeatedly.
#
#   bash teardown.sh [-y]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$HERE/terraform"
STATE_DIR="$HERE/.state"
REGION="${REGION:-us-east-1}"
AUTO_APPROVE="false"
[[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]] && AUTO_APPROVE="true"
export AWS_DEFAULT_REGION="$REGION"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo unknown)"
say "Teardown in account $ACCOUNT region $REGION"
if [[ "$AUTO_APPROVE" != "true" ]]; then
  read -r -p "Proceed with teardown? [y/N] " C
  [[ "$C" == "y" || "$C" == "Y" ]] || { echo "Aborted."; exit 1; }
fi

# --- 1. Stratus cleanup (reverts shared snapshots, backdoor policies, admin users) ---
if [[ -f "$STATE_DIR/stratus_detonated" ]] && command -v stratus >/dev/null 2>&1; then
  say "Stratus cleanup"
  while read -r t; do
    [[ -z "$t" ]] && continue
    echo "-> cleanup $t"
    stratus cleanup "$t" || warn "cleanup failed for $t (check manually)"
  done < "$STATE_DIR/stratus_detonated"
  rm -f "$STATE_DIR/stratus_detonated"
fi

# --- 2. Disable detection services we enabled ------------------------------
if [[ -f "$STATE_DIR/macie_enabled" ]]; then
  say "Disabling Macie"
  aws macie2 disable-macie || warn "macie disable failed"
  rm -f "$STATE_DIR/macie_enabled"
fi

if [[ -f "$STATE_DIR/securityhub_enabled" ]]; then
  say "Disabling Security Hub"
  aws securityhub disable-security-hub || warn "securityhub disable failed"
  rm -f "$STATE_DIR/securityhub_enabled"
fi

if [[ -f "$STATE_DIR/guardduty_created" ]]; then
  say "Deleting GuardDuty detector"
  DET="$(cat "$STATE_DIR/guardduty_created")"
  aws guardduty delete-detector --detector-id "$DET" || warn "guardduty delete failed"
  rm -f "$STATE_DIR/guardduty_created"
fi

# --- 3. Destroy infrastructure ---------------------------------------------
say "Terraform destroy"
TF_VAR_enable_config="$([[ "${ENABLE_CONFIG:-0}" == "1" ]] && echo true || echo false)"
terraform -chdir="$TF_DIR" destroy -input=false -auto-approve \
  -var "region=$REGION" -var "enable_config=$TF_VAR_enable_config" || \
  warn "terraform destroy reported errors — check the console for stragglers"

say "Teardown complete. Verify in the console that GuardDuty/Security Hub/Macie are off and no harbor-test-* resources remain."
