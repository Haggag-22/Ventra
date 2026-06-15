#!/usr/bin/env bash
# Phase 2 — Data Generation for the Ventra logging-test stack.
#
# Reads the Terraform outputs from testing/terraform and drives real activity so the
# 7 content-parsing collectors actually have records to find:
#   CloudTrail, VPC Flow, S3 access, ALB access, CloudFront access,
#   Route53 Resolver query logs, EKS audit
# Plus GuardDuty sample findings and an AWS Config change record.
#
# Usage:
#   AWS_PROFILE=stratus bash testing/generate-data.sh
#
# Env toggles:
#   REGION=us-east-1   override region (default: terraform output)
#   LOOPS=25           how many times to hit each HTTP endpoint
#   SKIP_HOST=1        skip the host-dependent best-effort steps (flow/resolver via SSM)
#   SKIP_EKS=1         skip the kubectl/EKS-audit step
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$HERE/terraform"
LOOPS="${LOOPS:-25}"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '   \033[1;33m! %s\033[0m\n' "$*"; }

command -v terraform >/dev/null 2>&1 || { echo "terraform not found"; exit 1; }
command -v aws        >/dev/null 2>&1 || { echo "aws CLI not found"; exit 1; }

tfout() { terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null; }
tfjson(){ terraform -chdir="$TF_DIR" output -json "$1" 2>/dev/null; }
jget()  { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }

REGION="${REGION:-$(tfout region)}"
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

ALB="$(tfout alb_dns_name)"
CF="$(tfout cloudfront_domain)"
API="$(tfout api_invoke_url)"
LAMBDA="$(tfout lambda_function)"
DDB="$(tfout dynamodb_table)"
INSTANCE="$(tfout instance_id)"
NAME_PREFIX="$(tfout name_prefix)"
APP_BUCKET="$(tfjson inventory_buckets | jget app)"
RDS_HOST="$(tfjson tier3_endpoints | jget rds)"
SUFFIX="${NAME_PREFIX#logging-test-}"
EKS_CLUSTER="lt-${SUFFIX}-eks"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
say "Target account $ACCOUNT  region $REGION  (prefix $NAME_PREFIX)"
warn "SANDBOX ONLY — this generates real (cheap) activity and attacker-looking requests."

# --- 1. CloudTrail: a batch of management-plane API calls --------------------
say "CloudTrail — management API calls"
for _ in $(seq 1 5); do
  aws sts get-caller-identity >/dev/null 2>&1
  aws ec2 describe-instances --max-items 5 >/dev/null 2>&1
  aws s3api list-buckets >/dev/null 2>&1
  aws iam list-users --max-items 5 >/dev/null 2>&1
done
ok "issued read API calls (recorded by CloudTrail within ~5-15 min)"

# --- 2. AWS Config: force a configuration change record ----------------------
say "AWS Config — force a change record"
if [[ "$INSTANCE" == i-* ]]; then
  aws ec2 create-tags --resources "$INSTANCE" \
    --tags "Key=ventra-datagen,Value=$(date -u +%s)" >/dev/null 2>&1 \
    && ok "tagged instance $INSTANCE (Config records the change)" \
    || warn "could not tag instance (Config step skipped)"
else
  warn "no EC2 instance output — skipping Config change"
fi

# --- 3. ALB access logs + WAF (HTTP, incl. attacker-looking requests) --------
if [[ -n "$ALB" ]]; then
  say "ALB access logs + WAF — $LOOPS requests to http://$ALB"
  for _ in $(seq 1 "$LOOPS"); do
    curl -s -o /dev/null --max-time 5 "http://$ALB/" || true
    curl -s -o /dev/null --max-time 5 "http://$ALB/?id=1%27%20OR%20%271%27=%271" || true
    curl -s -o /dev/null --max-time 5 -A "() { :; }; /bin/bash" "http://$ALB/admin" || true
  done
  ok "ALB hit (access logs flush to S3 in ~5 min)"
else
  warn "no alb_dns_name — skipping ALB"
fi

# --- 4. CloudFront access logs ---------------------------------------------
if [[ -n "$CF" ]]; then
  say "CloudFront access logs — $LOOPS requests to https://$CF"
  for _ in $(seq 1 "$LOOPS"); do
    curl -s -o /dev/null --max-time 8 "https://$CF/" || true
  done
  ok "CloudFront hit (access logs flush to S3, can take 10-60 min)"
else
  warn "no cloudfront_domain — skipping CloudFront"
fi

# --- 5. API Gateway access logs --------------------------------------------
if [[ -n "$API" ]]; then
  say "API Gateway access logs — $LOOPS calls to $API"
  for _ in $(seq 1 "$LOOPS"); do
    curl -s -o /dev/null --max-time 5 "$API" || true
  done
  ok "API Gateway called (access logs to CloudWatch within ~1-2 min)"
else
  warn "no api_invoke_url — skipping API Gateway"
fi

# --- 6. Lambda invocations -------------------------------------------------
if [[ -n "$LAMBDA" ]]; then
  say "Lambda — invoking $LAMBDA"
  for _ in $(seq 1 5); do
    aws lambda invoke --function-name "$LAMBDA" --payload '{}' /tmp/ventra-lambda-out.json >/dev/null 2>&1 || true
  done
  ok "Lambda invoked (logs to /aws/lambda/$LAMBDA)"
else
  warn "no lambda_function — skipping Lambda"
fi

# --- 7. S3 access logs: PUT/GET on the app bucket --------------------------
if [[ -n "$APP_BUCKET" ]]; then
  say "S3 access logs — PUT/GET on s3://$APP_BUCKET"
  echo "ventra datagen $(date -u)" > /tmp/ventra-s3-obj.txt
  for i in $(seq 1 "$LOOPS"); do
    aws s3 cp /tmp/ventra-s3-obj.txt "s3://$APP_BUCKET/datagen/obj-$i.txt" >/dev/null 2>&1 || true
    aws s3 cp "s3://$APP_BUCKET/datagen/obj-$i.txt" /tmp/ventra-s3-get.txt >/dev/null 2>&1 || true
  done
  ok "S3 objects written/read (server access logs flush in ~1h, sometimes faster)"
else
  warn "no app bucket — skipping S3 access logs"
fi

# --- 8. DynamoDB writes (streams) -----------------------------------------
if [[ -n "$DDB" ]]; then
  say "DynamoDB — put/update/delete on $DDB"
  for i in $(seq 1 "$LOOPS"); do
    aws dynamodb put-item --table-name "$DDB" \
      --item "{\"id\":{\"S\":\"item-$i\"},\"v\":{\"N\":\"$i\"}}" >/dev/null 2>&1 || true
    aws dynamodb update-item --table-name "$DDB" \
      --key "{\"id\":{\"S\":\"item-$i\"}}" \
      --update-expression "SET v = :v" \
      --expression-attribute-values "{\":v\":{\"N\":\"$((i*2))\"}}" >/dev/null 2>&1 || true
    aws dynamodb delete-item --table-name "$DDB" \
      --key "{\"id\":{\"S\":\"item-$i\"}}" >/dev/null 2>&1 || true
  done
  ok "DynamoDB items churned (stream records produced)"
else
  warn "no dynamodb_table — skipping DynamoDB"
fi

# --- 9. GuardDuty sample findings -----------------------------------------
say "GuardDuty — sample findings"
DETECTOR="$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null || echo None)"
if [[ -n "$DETECTOR" && "$DETECTOR" != "None" ]]; then
  aws guardduty create-sample-findings --detector-id "$DETECTOR" >/dev/null 2>&1 \
    && ok "sample findings generated on detector $DETECTOR" \
    || warn "create-sample-findings failed"
else
  warn "no GuardDuty detector found"
fi

# --- 10. VPC Flow + Route53 Resolver (host-dependent, best effort via SSM) --
if [[ "${SKIP_HOST:-0}" != "1" && "$INSTANCE" == i-* ]]; then
  say "VPC Flow + Route53 Resolver — driving traffic from $INSTANCE via SSM"
  CMD_ID="$(aws ssm send-command \
    --instance-ids "$INSTANCE" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["for d in example.com aws.amazon.com github.com cloudflare.com; do nslookup $d; curl -s -o /dev/null https://$d; done"]' \
    --query 'Command.CommandId' --output text 2>/dev/null || echo '')"
  if [[ -n "$CMD_ID" ]]; then
    ok "SSM command $CMD_ID sent (DNS + outbound traffic → flow + resolver logs)"
  else
    warn "SSM unavailable (no agent/instance profile). Flow logs still capture boot traffic;"
    warn "resolver query logs may be sparse without in-VPC DNS activity."
  fi
else
  warn "skipping host-dependent flow/resolver generation (SKIP_HOST=1 or no instance)"
fi

# --- 11. EKS audit logs (best effort, needs kubectl) -----------------------
if [[ "${SKIP_EKS:-0}" != "1" ]] && aws eks describe-cluster --name "$EKS_CLUSTER" >/dev/null 2>&1; then
  say "EKS audit — generating k8s API activity on $EKS_CLUSTER"
  if command -v kubectl >/dev/null 2>&1; then
    aws eks update-kubeconfig --name "$EKS_CLUSTER" --region "$REGION" >/dev/null 2>&1 || true
    for _ in $(seq 1 5); do
      kubectl get ns >/dev/null 2>&1 || true
      kubectl get pods -A >/dev/null 2>&1 || true
      kubectl auth can-i --list >/dev/null 2>&1 || true
    done
    ok "kubectl calls issued (audit log stream fills within a few minutes)"
  else
    warn "kubectl not installed — EKS audit needs k8s API calls. Install kubectl or run a few"
    warn "kubectl commands manually after: aws eks update-kubeconfig --name $EKS_CLUSTER"
  fi
else
  warn "EKS cluster not found or SKIP_EKS=1 — skipping EKS audit generation"
fi

say "Data generation complete."
cat <<EOF

Now WAIT for logs to flush before running the collector:
  - API Gateway / Lambda / EKS audit ... ~1-5 min
  - CloudTrail / ALB / VPC Flow ......... ~5-15 min
  - CloudFront / S3 access .............. ~10-60 min

Then run the Ventra collector against account $ACCOUNT in $REGION.
EOF
