#!/usr/bin/env bash
# Harbor live-test driver: stand up infra, enable detection services, generate findings,
# optionally run Stratus attacks, then run the collector. Pair with teardown.sh.
#
#   bash run-test.sh [-y]
#
# Env toggles:
#   WITH_STRATUS=1   also detonate a Stratus Red Team subset (needs `stratus` on PATH)
#   WITH_MACIE=1     also enable Macie + run a PII classification job (slow, extra cost)
#   ENABLE_CONFIG=1  also stand up an AWS Config recorder (passed to Terraform)
#   REGION=us-east-1 override the deploy region
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$HERE/terraform"
STATE_DIR="$HERE/.state"
OUT_DIR="$HERE/out"
REGION="${REGION:-us-east-1}"
CASE_ID="${CASE_ID:-CASE-LIVE-$(date -u +%Y%m%d)}"
AUTO_APPROVE="false"
[[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]] && AUTO_APPROVE="true"

mkdir -p "$STATE_DIR" "$OUT_DIR"
export AWS_DEFAULT_REGION="$REGION"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { warn "missing required tool: $1"; exit 1; }; }

need aws
need terraform
command -v harbor-collect >/dev/null 2>&1 || warn "harbor-collect not on PATH — install with 'pip install -e .' from the repo root (collection step will fail without it)"

# --- safety gate -----------------------------------------------------------
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
CALLER="$(aws sts get-caller-identity --query Arn --output text)"
say "Target account: $ACCOUNT  region: $REGION"
echo "Caller: $CALLER"
warn "This creates real (cheap) resources and attacker-looking activity. SANDBOX ACCOUNTS ONLY."
if [[ "$AUTO_APPROVE" != "true" ]]; then
  read -r -p "Type the account id ($ACCOUNT) to proceed: " CONFIRM
  [[ "$CONFIRM" == "$ACCOUNT" ]] || { echo "Aborted."; exit 1; }
fi

# --- 1. infrastructure -----------------------------------------------------
say "Terraform apply"
TF_VAR_enable_config="$([[ "${ENABLE_CONFIG:-0}" == "1" ]] && echo true || echo false)"
terraform -chdir="$TF_DIR" init -input=false
terraform -chdir="$TF_DIR" apply -input=false -auto-approve \
  -var "region=$REGION" -var "enable_config=$TF_VAR_enable_config"
PII_BUCKET="$(terraform -chdir="$TF_DIR" output -raw pii_bucket)"

# --- 2. GuardDuty: enable + sample findings --------------------------------
say "GuardDuty"
DETECTOR="$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null || echo None)"
if [[ "$DETECTOR" == "None" || -z "$DETECTOR" ]]; then
  DETECTOR="$(aws guardduty create-detector --enable --query DetectorId --output text)"
  echo "$DETECTOR" > "$STATE_DIR/guardduty_created"
  echo "created detector $DETECTOR"
else
  echo "using existing detector $DETECTOR (will not disable on teardown)"
fi
aws guardduty create-sample-findings --detector-id "$DETECTOR" >/dev/null \
  && echo "sample findings generated"

# --- 3. Security Hub -------------------------------------------------------
say "Security Hub"
if aws securityhub enable-security-hub --enable-default-standards 2>/dev/null; then
  touch "$STATE_DIR/securityhub_enabled"
  echo "enabled (findings populate from the misconfigs within ~1h)"
else
  echo "already enabled or unavailable — leaving as-is"
fi

# --- 4. Macie (optional) ---------------------------------------------------
if [[ "${WITH_MACIE:-0}" == "1" ]]; then
  say "Macie"
  if aws macie2 enable-macie 2>/dev/null; then
    touch "$STATE_DIR/macie_enabled"
    echo "enabled"
  else
    echo "already enabled — leaving as-is"
  fi
  JOB_ID="$(aws macie2 create-classification-job \
    --job-type ONE_TIME \
    --name "harbor-test-$(date -u +%H%M%S)" \
    --s3-job-definition "{\"bucketDefinitions\":[{\"accountId\":\"$ACCOUNT\",\"buckets\":[\"$PII_BUCKET\"]}]}" \
    --query jobId --output text 2>/dev/null || echo '')"
  [[ -n "$JOB_ID" ]] && echo "classification job $JOB_ID started (takes 10–30 min to surface findings)"
fi

# --- 5. Stratus Red Team (optional) ----------------------------------------
if [[ "${WITH_STRATUS:-0}" == "1" ]]; then
  say "Stratus Red Team"
  if command -v stratus >/dev/null 2>&1; then
    # Edit this list freely. cloudtrail-stop is omitted by default so it doesn't
    # suppress logging of the other techniques mid-run.
    TECHNIQUES=(
      "aws.exfiltration.ec2-share-ebs-snapshot"
      "aws.persistence.iam-create-admin-user"
      "aws.exfiltration.s3-backdoor-bucket-policy"
    )
    printf '%s\n' "${TECHNIQUES[@]}" > "$STATE_DIR/stratus_detonated"
    for t in "${TECHNIQUES[@]}"; do
      echo "-> detonating $t"
      stratus detonate "$t" || warn "detonate failed for $t (continuing)"
    done
  else
    warn "stratus not installed — skipping attack step (see README for install)"
  fi
fi

# --- 6. Run the collector --------------------------------------------------
say "Harbor collect"
SINCE="$(date -u +%Y-%m-%d)"
if command -v harbor-collect >/dev/null 2>&1; then
  harbor-collect aws --case "$CASE_ID" --regions "$REGION" --since "$SINCE" --out "$OUT_DIR"
  PKG="$(ls -t "$OUT_DIR"/case-*.tar.* 2>/dev/null | grep -v '.sha256' | head -1 || true)"
  echo "package: ${PKG:-<none>}"
else
  warn "harbor-collect missing — skipped. Install it and run:"
  echo "  harbor-collect aws --case $CASE_ID --regions $REGION --since $SINCE --out $OUT_DIR"
fi

say "Done. Review the package's manifest.json (sources + gaps), then run: bash teardown.sh"
