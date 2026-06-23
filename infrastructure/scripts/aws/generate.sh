#!/usr/bin/env bash
# Ventra AWS lab traffic + lab-native MITRE technique simulation (single script).
# Uses existing Terraform lab resources only — no Stratus Red Team infrastructure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common.sh"

AWS_DIR="${AWS_DIR:-${VENTRA_INFRA_ROOT}/aws}"
AWS_PROFILE="${AWS_PROFILE:-}"
AWS_REGION="${AWS_REGION:-}"
FAKE_ACCOUNT="${FAKE_ACCOUNT:-193672423079}"

parse_common_args "$@"

require_cmd aws
require_cmd curl
require_cmd jq

section "Loading Terraform outputs from ${AWS_DIR}"
load_tf_json "$AWS_DIR" TF_JSON
REGION="$(tf_out "$TF_JSON" region)"
REGION="${AWS_REGION:-$REGION}"
ALB_DNS="$(tf_out "$TF_JSON" alb_dns_name)"
APP_BUCKET="$(tf_out "$TF_JSON" app_data_bucket)"
LAMBDA_NAME="$(tf_out "$TF_JSON" lambda_function_name)"
KMS_ARN="$(tf_out "$TF_JSON" kms_key_arn)"
SECRET_ARN="$(tf_out "$TF_JSON" secrets_manager_secret_arn)"
CF_DIST="$(tf_out "$TF_JSON" cloudfront_distribution_id)"
EKS_CLUSTER="$(tf_out "$TF_JSON" eks_cluster_name)"
TRAIL_NAME="$(tf_out "$TF_JSON" cloudtrail_trail_name)"
VPC_ID="$(tf_out "$TF_JSON" vpc_id)"
CLOUDTRAIL_BUCKET="$(tf_out "$TF_JSON" cloudtrail_bucket)"

aws_cli() { run aws ${AWS_PROFILE:+--profile "$AWS_PROFILE"} --region "$REGION" "$@"; }

gen_http_traffic() {
  section "HTTP edge traffic (ALB, CloudFront, WAF)"
  local i cf_domain
  for ((i = 1; i <= ITERATIONS; i++)); do
    [[ -n "$ALB_DNS" ]] && retry_http "http://${ALB_DNS}/" "ALB" || true
    [[ -n "$ALB_DNS" ]] && retry_http "http://${ALB_DNS}/?run=${i}" "ALB query" || true
    if [[ -n "$CF_DIST" && "$CF_DIST" != "null" ]]; then
      cf_domain="$(aws_cli cloudfront get-distribution --id "$CF_DIST" \
        --query 'Distribution.DomainName' --output text 2>/dev/null || true)"
      [[ -n "$cf_domain" && "$cf_domain" != "None" ]] \
        && retry_http "https://${cf_domain}/index.html" "CloudFront" || true
    fi
    pause_between
  done
}

gen_s3_activity() {
  section "S3 object activity"
  [[ -z "$APP_BUCKET" ]] && { warn "no app_data_bucket output"; return; }
  local i key tmp
  tmp="$(mktemp)"
  echo "ventra,aws,$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$tmp"
  for ((i = 1; i <= ITERATIONS; i++)); do
    key="traffic/run-$(date +%s)-${i}.csv"
    aws_cli s3 ls "s3://${APP_BUCKET}/" >/dev/null 2>&1 && ok "s3:ListBucket" || warn "s3:ListBucket"
    aws_cli s3 cp "$tmp" "s3://${APP_BUCKET}/${key}" >/dev/null 2>&1 && ok "s3:PutObject" || warn "s3:PutObject"
    aws_cli s3 cp "s3://${APP_BUCKET}/samples/demo-object.txt" - >/dev/null 2>&1 && ok "s3:GetObject" || warn "s3:GetObject"
    pause_between
  done
  rm -f "$tmp"
}

gen_lambda_apigw() {
  section "Lambda + API Gateway"
  [[ -z "$LAMBDA_NAME" ]] && return
  local i api_id stage_url payload='{"source":"ventra-lab"}'
  for ((i = 1; i <= ITERATIONS; i++)); do
    aws_cli lambda invoke --function-name "$LAMBDA_NAME" \
      --payload "$payload" --cli-binary-format raw-in-base64-out \
      /tmp/ventra-lambda-out.json >/dev/null 2>&1 && ok "lambda:Invoke" || warn "lambda:Invoke"
    api_id="$(aws_cli apigateway get-rest-apis \
      --query "items[?contains(name,'ventra') || contains(name,'lab')].id | [0]" -o text 2>/dev/null || true)"
    if [[ -n "$api_id" && "$api_id" != "None" ]]; then
      stage_url="https://${api_id}.execute-api.${REGION}.amazonaws.com/prod/hello"
      retry_http "$stage_url" "API Gateway" || true
    fi
    pause_between
  done
}

gen_crypto_secrets() {
  section "KMS + Secrets Manager (audit events — values not printed)"
  if [[ -n "$KMS_ARN" ]]; then
    aws_cli kms encrypt --key-id "$KMS_ARN" --plaintext "ventra-lab" \
      --query CiphertextBlob --output text >/dev/null 2>&1 && ok "kms:Encrypt" || warn "kms:Encrypt"
  fi
  if [[ -n "$SECRET_ARN" ]]; then
    aws_cli secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query Name -o text >/dev/null 2>&1 \
      && ok "secretsmanager:GetSecretValue" || warn "secretsmanager"
  fi
}

gen_dynamodb() {
  section "DynamoDB writes"
  local table i
  table="$(aws_cli dynamodb list-tables \
    --query "TableNames[?contains(@,'ventra') || contains(@,'lab')] | [0]" -o text 2>/dev/null || true)"
  [[ -z "$table" || "$table" == "None" ]] && { warn "no lab DynamoDB table"; return; }
  for ((i = 1; i <= ITERATIONS; i++)); do
    aws_cli dynamodb put-item --table-name "$table" \
      --item "{\"pk\":{\"S\":\"traffic-${i}-$(date +%s)\"}}" >/dev/null 2>&1 \
      && ok "dynamodb:PutItem" || warn "dynamodb:PutItem"
    pause_between
  done
}

gen_control_plane() {
  section "Control-plane reads (CloudTrail management events)"
  aws_cli sts get-caller-identity >/dev/null 2>&1 && ok "sts:GetCallerIdentity"
  aws_cli iam list-users --max-items 5 >/dev/null 2>&1 && ok "iam:ListUsers"
  aws_cli ec2 describe-instances --max-results 5 >/dev/null 2>&1 && ok "ec2:DescribeInstances"
  aws_cli ec2 describe-flow-logs >/dev/null 2>&1 && ok "ec2:DescribeFlowLogs"
  aws_cli cloudtrail lookup-events --max-results 5 >/dev/null 2>&1 && ok "cloudtrail:LookupEvents"
  aws_cli guardduty list-detectors >/dev/null 2>&1 && ok "guardduty:ListDetectors"
}

eks_kubeconfig() {
  [[ -z "$EKS_CLUSTER" || "$EKS_CLUSTER" == "null" ]] && return 1
  command -v kubectl >/dev/null 2>&1 || { warn "kubectl missing"; return 1; }
  aws_cli eks update-kubeconfig --name "$EKS_CLUSTER" >/dev/null 2>&1
}

gen_eks_audit() {
  section "EKS audit logs"
  eks_kubeconfig || return
  kubectl get pods -A >/dev/null 2>&1 && ok "kubectl get pods (EKS audit)"
}

gen_route53_dns() {
  section "Route53 Resolver query logs (in-VPC DNS via EKS)"
  eks_kubeconfig || { warn "EKS required for in-VPC DNS — resolver logs need queries from VPC ENIs"; return; }
  local i pod_name phase
  for ((i = 1; i <= ITERATIONS; i++)); do
    pod_name="ventra-dns-${i}-$(date +%s)"
    local cmd="nslookup amazon.com; nslookup s3.amazonaws.com; nslookup ec2.${REGION}.amazonaws.com"
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "  [dry-run] kubectl run ${pod_name} --restart=Never --image=busybox:1.36 -- sh -c '${cmd}'"
      pause_between
      continue
    fi
    kubectl run "$pod_name" --restart=Never --image=busybox:1.36 --command -- sh -c "$cmd" >/dev/null 2>&1 \
      && ok "started DNS probe pod ${pod_name}" || { warn "kubectl run failed"; continue; }
    local wait=0
    while [[ $wait -lt 45 ]]; do
      phase="$(kubectl get pod "$pod_name" -o jsonpath='{.status.phase}' 2>/dev/null || echo Pending)"
      [[ "$phase" == "Succeeded" || "$phase" == "Failed" ]] && break
      sleep 2
      wait=$((wait + 2))
    done
    ok "in-VPC DNS queries → resolver logs (pod ${pod_name}: ${phase})"
    kubectl delete pod "$pod_name" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    pause_between
  done
}

lab_instance_id() {
  aws_cli ec2 describe-instances \
    --filters \
      "Name=tag:Purpose,Values=ventra-collector-lab" \
      "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null \
    | { read -r id; [[ -n "$id" && "$id" != "None" ]] && echo "$id" || true; }
}

run_technique() {
  local id="$1" fn="$2"
  section "Technique: ${id}"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "  [dry-run] would run ${fn}"
    return 0
  fi
  if "$fn"; then ok "${id}"; else warn "${id} (partial or skipped)"; fi
  pause_between
}

tech_discovery_ec2_download_user_data() {
  local iid
  iid="$(lab_instance_id)"
  [[ -z "$iid" ]] && { warn "no lab EC2"; return 1; }
  aws_cli ec2 describe-instance-attribute --instance-id "$iid" --attribute userData >/dev/null \
    && ok "ec2:DescribeInstanceAttribute userData on ${iid}"
}

tech_discovery_ses_enumerate() {
  aws_cli ses list-identities >/dev/null 2>&1 && ok "ses:ListIdentities" || warn "ses:ListIdentities"
  aws_cli sesv2 list-email-identities --page-size 10 >/dev/null 2>&1 && ok "sesv2:ListEmailIdentities" || true
}

tech_credential_access_secretsmanager_retrieve() {
  [[ -z "$SECRET_ARN" ]] && return 1
  aws_cli secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query Name --output text >/dev/null \
    && ok "secretsmanager:GetSecretValue"
  aws_cli secretsmanager list-secrets --max-results 10 >/dev/null 2>&1 && ok "secretsmanager:ListSecrets"
}

tech_credential_access_secretsmanager_batch() {
  [[ -z "$SECRET_ARN" ]] && return 1
  aws_cli secretsmanager batch-get-secret-value --secret-id-list "$SECRET_ARN" >/dev/null 2>&1 \
    && ok "secretsmanager:BatchGetSecretValue" || warn "batch-get (API may need 2+ secrets)"
}

tech_credential_access_ec2_get_password_data() {
  local iid
  iid="$(lab_instance_id)"
  [[ -z "$iid" ]] && return 1
  aws_cli ec2 get-password-data --instance-id "$iid" >/dev/null 2>&1 \
    && ok "ec2:GetPasswordData" || ok "ec2:GetPasswordData (expected fail on Linux)"
}

tech_exfiltration_s3_backdoor_bucket_policy() {
  [[ -z "$APP_BUCKET" ]] && return 1
  local backup policy restored=0
  backup="$(mktemp)"
  if aws_cli s3api get-bucket-policy --bucket "$APP_BUCKET" --query Policy --output text >"$backup" 2>/dev/null; then
    :
  else
    echo '{}' >"$backup"
  fi
  policy="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "VentraSimExternalAccess",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::${FAKE_ACCOUNT}:root"},
    "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
    "Resource": ["arn:aws:s3:::${APP_BUCKET}", "arn:aws:s3:::${APP_BUCKET}/*"]
  }]
}
EOF
)"
  aws_cli s3api put-bucket-policy --bucket "$APP_BUCKET" --policy "$policy" >/dev/null \
    && ok "s3:PutBucketPolicy backdoor (simulated external account)"
  if [[ "$(cat "$backup")" != "{}" ]]; then
    aws_cli s3api put-bucket-policy --bucket "$APP_BUCKET" --policy "$(cat "$backup")" >/dev/null \
      && restored=1
  else
    aws_cli s3api delete-bucket-policy --bucket "$APP_BUCKET" >/dev/null 2>&1 && restored=1 || true
  fi
  rm -f "$backup"
  [[ "$restored" == "1" ]] && ok "restored original bucket policy"
}

tech_persistence_lambda_backdoor_function() {
  [[ -z "$LAMBDA_NAME" ]] && return 1
  aws_cli lambda update-function-configuration \
    --function-name "$LAMBDA_NAME" \
    --environment "Variables={VENTRA_SIM_BACKDOOR=1}" >/dev/null \
    && ok "lambda:UpdateFunctionConfiguration (suspicious env)"
  aws_cli lambda update-function-configuration \
    --function-name "$LAMBDA_NAME" --environment "Variables={}" >/dev/null 2>&1 \
    && ok "restored lambda environment"
}

tech_persistence_iam_create_admin_user() {
  local user="ventra-sim-admin-$(date +%s)"
  aws_cli iam create-user --user-name "$user" >/dev/null
  aws_cli iam attach-user-policy --user-name "$user" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess >/dev/null \
    && ok "iam:CreateUser + AdministratorAccess on ${user}"
  aws_cli iam detach-user-policy --user-name "$user" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess >/dev/null 2>&1 || true
  aws_cli iam delete-user --user-name "$user" >/dev/null 2>&1 && ok "deleted ${user}"
}

tech_persistence_iam_backdoor_user() {
  local user
  user="$(aws_cli iam list-users --query "Users[?contains(UserName,'readonly')].UserName | [0]" --output text 2>/dev/null || true)"
  [[ -z "$user" || "$user" == "None" ]] && { warn "no lab readonly IAM user"; return 1; }
  aws_cli iam attach-user-policy --user-name "$user" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess >/dev/null \
    && ok "iam:AttachUserPolicy admin on existing ${user}"
  aws_cli iam detach-user-policy --user-name "$user" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess >/dev/null \
    && ok "detached admin from ${user}"
}

tech_persistence_sts_federation_token() {
  aws_cli sts get-federation-token --name ventra-sim \
    --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListAllMyBuckets"],"Resource":"*"}]}' \
    >/dev/null 2>&1 && ok "sts:GetFederationToken" || warn "sts:GetFederationToken (may need IAM permission)"
}

tech_defense_evasion_cloudtrail_stop() {
  [[ -z "$TRAIL_NAME" ]] && return 1
  aws_cli cloudtrail stop-logging --name "$TRAIL_NAME" >/dev/null && ok "cloudtrail:StopLogging"
  sleep 2
  aws_cli cloudtrail start-logging --name "$TRAIL_NAME" >/dev/null && ok "cloudtrail:StartLogging (restored)"
}

tech_defense_evasion_cloudtrail_lifecycle_rule() {
  [[ -z "$CLOUDTRAIL_BUCKET" ]] && return 1
  aws_cli s3api put-bucket-lifecycle-configuration --bucket "$CLOUDTRAIL_BUCKET" \
    --lifecycle-configuration '{"Rules":[{"ID":"ventra-sim-expire","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":3650}}]}' \
    >/dev/null 2>&1 && ok "s3:PutBucketLifecycleConfiguration on CloudTrail bucket"
  aws_cli s3api delete-bucket-lifecycle --bucket "$CLOUDTRAIL_BUCKET" >/dev/null 2>&1 \
    && ok "removed sim lifecycle rule"
}

tech_defense_evasion_dns_delete_logs() {
  local cfg
  cfg="$(aws_cli route53resolver list-resolver-query-log-configs \
    --query "ResolverQueryLogConfigs[?contains(Name,'ventra') || contains(Name,'lab')].Id | [0]" \
    --output text 2>/dev/null || true)"
  [[ -z "$cfg" || "$cfg" == "None" ]] && { warn "no resolver query log config"; return 1; }
  aws_cli route53resolver get-resolver-query-log-config --resolver-query-log-config-id "$cfg" >/dev/null \
    && ok "route53resolver:GetResolverQueryLogConfig (describe only — logs preserved)"
}

tech_lateral_movement_ec2_instance_connect() {
  local iid az pubkey
  iid="$(lab_instance_id)"
  [[ -z "$iid" ]] && return 1
  az="$(aws_cli ec2 describe-instances --instance-ids "$iid" \
    --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)"
  command -v ssh-keygen >/dev/null 2>&1 || { warn "ssh-keygen missing"; return 1; }
  pubkey="$(ssh-keygen -t rsa -N '' -f /tmp/ventra-sim-eic -q && cat /tmp/ventra-sim-eic.pub)"
  aws_cli ec2-instance-connect send-ssh-public-key \
    --instance-id "$iid" --availability-zone "$az" --instance-os-user ec2-user \
    --ssh-public-key "$pubkey" >/dev/null 2>&1 \
    && ok "ec2-instance-connect:SendSSHPublicKey on ${iid}"
  rm -f /tmp/ventra-sim-eic /tmp/ventra-sim-eic.pub
}

tech_privilege_escalation_iam_update_login_profile() {
  local user="ventra-sim-login-$(date +%s)"
  aws_cli iam create-user --user-name "$user" >/dev/null
  aws_cli iam create-login-profile --user-name "$user" \
    --password 'VentraSim1!' --no-password-reset-required >/dev/null 2>&1 \
    && ok "iam:CreateLoginProfile on ${user}"
  aws_cli iam delete-login-profile --user-name "$user" >/dev/null 2>&1 || true
  aws_cli iam delete-user --user-name "$user" >/dev/null 2>&1 && ok "deleted ${user}"
}

run_all_techniques() {
  section "Lab-native MITRE techniques (existing infra only)"
  run_technique "aws.discovery.ec2-download-user-data" tech_discovery_ec2_download_user_data
  run_technique "aws.discovery.ses-enumerate" tech_discovery_ses_enumerate
  run_technique "aws.credential-access.secretsmanager-retrieve-secrets" tech_credential_access_secretsmanager_retrieve
  run_technique "aws.credential-access.secretsmanager-batch-retrieve-secrets" tech_credential_access_secretsmanager_batch
  run_technique "aws.credential-access.ec2-get-password-data" tech_credential_access_ec2_get_password_data
  run_technique "aws.exfiltration.s3-backdoor-bucket-policy" tech_exfiltration_s3_backdoor_bucket_policy
  run_technique "aws.persistence.lambda-backdoor-function" tech_persistence_lambda_backdoor_function
  run_technique "aws.persistence.iam-create-admin-user" tech_persistence_iam_create_admin_user
  run_technique "aws.persistence.iam-backdoor-user" tech_persistence_iam_backdoor_user
  run_technique "aws.persistence.sts-federation-token" tech_persistence_sts_federation_token
  run_technique "aws.defense-evasion.cloudtrail-stop" tech_defense_evasion_cloudtrail_stop
  run_technique "aws.defense-evasion.cloudtrail-lifecycle-rule" tech_defense_evasion_cloudtrail_lifecycle_rule
  run_technique "aws.defense-evasion.dns-delete-logs" tech_defense_evasion_dns_delete_logs
  run_technique "aws.lateral-movement.ec2-instance-connect" tech_lateral_movement_ec2_instance_connect
  run_technique "aws.privilege-escalation.iam-update-user-login-profile" tech_privilege_escalation_iam_update_login_profile
}

main() {
  echo -e "${GREEN}Ventra AWS lab generator${NC} (iterations=${ITERATIONS}, dry_run=${DRY_RUN})"
  gen_http_traffic
  gen_s3_activity
  gen_lambda_apigw
  gen_crypto_secrets
  gen_dynamodb
  gen_control_plane
  gen_eks_audit
  gen_route53_dns
  run_all_techniques
  summary_box "AWS" \
    "Edge: ALB + CloudFront + WAF access logs" \
    "Data: S3, Lambda, DynamoDB, API Gateway" \
    "Audit: EKS + Route53 Resolver (in-VPC DNS via EKS)" \
    "Security: KMS, Secrets, CloudTrail techniques" \
    "MITRE: 15 lab-native techniques (no Stratus infra)"
}

main
