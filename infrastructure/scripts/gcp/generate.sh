#!/usr/bin/env bash
# Generate GCP lab traffic + API activity for Ventra collector testing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common.sh"

GCP_DIR="${GCP_DIR:-${VENTRA_INFRA_ROOT}/gcp}"
PROJECT_ID="${GCP_PROJECT_ID:-}"

parse_common_args "$@"

require_cmd gcloud
require_cmd curl
require_cmd jq

section "Loading Terraform outputs from ${GCP_DIR}"
load_tf_json "$GCP_DIR" TF_JSON
PROJECT_ID="${PROJECT_ID:-$(tf_out "$TF_JSON" project_id)}"
REGION="$(tf_out "$TF_JSON" region)"
LB_IP="$(tf_out "$TF_JSON" load_balancer_ip)"
APP_BUCKET="$(tf_out "$TF_JSON" app_bucket)"
CF_NAME="$(tf_out "$TF_JSON" cloud_function_name)"
API_GW_URL="$(tf_out "$TF_JSON" api_gateway_url)"

gcloud_cli() { run gcloud "$@" --project="$PROJECT_ID"; }

gen_http_traffic() {
  section "HTTP traffic (load balancer)"
  [[ -z "$LB_IP" || "$LB_IP" == "null" ]] && { warn "no load_balancer_ip"; return; }
  local i
  for ((i = 1; i <= ITERATIONS; i++)); do
    retry_http "http://${LB_IP}/" "HTTP LB" || true
    retry_http "http://${LB_IP}/?run=${i}" "HTTP LB query" || true
    pause_between
  done
}

gen_storage() {
  section "GCS object activity"
  [[ -z "$APP_BUCKET" ]] && return
  local i obj tmp
  tmp="$(mktemp)"
  echo "ventra,gcp,$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$tmp"
  for ((i = 1; i <= ITERATIONS; i++)); do
    obj="traffic/run-$(date +%s)-${i}.csv"
    gcloud_cli storage cp "$tmp" "gs://${APP_BUCKET}/${obj}" >/dev/null 2>&1 && ok "gcs upload" || warn "gcs upload"
    gcloud_cli storage cp "gs://${APP_BUCKET}/samples/demo-export.csv" /tmp/ventra-gcp-sample.csv >/dev/null 2>&1 \
      && ok "gcs download" || warn "gcs download"
    pause_between
  done
  rm -f "$tmp"
}

gen_cloud_function() {
  section "Cloud Functions"
  [[ -z "$CF_NAME" ]] && return
  local uri
  uri="$(gcloud_cli functions describe "$CF_NAME" --gen2 --region="$REGION" \
    --format='value(serviceConfig.uri)' 2>/dev/null || true)"
  [[ -n "$uri" ]] && retry_http "$uri" "Cloud Function HTTP" || true
  gcloud_cli functions call "$CF_NAME" --gen2 --region="$REGION" --data='{"source":"ventra-lab"}' >/dev/null 2>&1 \
    && ok "functions call" || warn "functions call"
}

gen_api_gateway() {
  section "API Gateway"
  [[ -z "$API_GW_URL" || "$API_GW_URL" == "null" ]] && { warn "API Gateway not deployed"; return; }
  retry_http "https://${API_GW_URL}/hello" "API Gateway /hello" || true
}

gen_control_plane() {
  section "Control-plane reads (cloud audit + IAM)"
  gcloud_cli projects describe "$PROJECT_ID" >/dev/null 2>&1 && ok "projects describe"
  gcloud_cli iam service-accounts list --limit=5 >/dev/null 2>&1 && ok "iam service-accounts list"
  gcloud_cli compute instances list --limit=5 >/dev/null 2>&1 && ok "compute instances list"
  gcloud_cli compute firewall-rules list --limit=5 >/dev/null 2>&1 && ok "firewall rules list"
  gcloud_cli logging read 'logName:"cloudaudit.googleapis.com"' --limit=5 --freshness=1d >/dev/null 2>&1 \
    && ok "logging read audit" || warn "logging read"
}

gen_vm_logs() {
  section "VM syslog (vm_logs via ops agent)"
  local zone instance
  zone="$(gcloud_cli compute instances list --limit=1 --format='value(zone.basename())' 2>/dev/null || true)"
  instance="$(gcloud_cli compute instances list --limit=1 --format='value(name)' 2>/dev/null || true)"
  [[ -z "$instance" || -z "$zone" ]] && { warn "no GCE instance"; return; }
  gcloud_cli compute ssh "$instance" --zone="$zone" --command="logger ventra-lab-traffic-$(date +%s)" \
    >/dev/null 2>&1 && ok "syslog on ${instance}" || warn "compute ssh (needs SSH/IAP access)"
}

main() {
  echo -e "${GREEN}Ventra GCP traffic generator${NC} (iterations=${ITERATIONS}, dry_run=${DRY_RUN})"
  gen_http_traffic
  gen_storage
  gen_cloud_function
  gen_api_gateway
  gen_control_plane
  gen_vm_logs
  summary_box "GCP" \
    "Edge: HTTP load balancer" \
    "Data: GCS + Cloud Functions" \
    "Control plane: audit log reads" \
    "Workspace audit: configure in Workspace admin separately"
}
main
