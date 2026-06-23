#!/usr/bin/env bash
# Generate Azure lab traffic + API activity for Ventra collector testing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common.sh"

AZURE_DIR="${AZURE_DIR:-${VENTRA_INFRA_ROOT}/azure}"
SUBSCRIPTION_ID="${AZ_SUBSCRIPTION_ID:-}"
LOCATION="${AZURE_LOCATION:-eastus}"

parse_common_args "$@"

require_cmd az
require_cmd curl
require_cmd jq

section "Loading Terraform outputs from ${AZURE_DIR}"
load_tf_json "$AZURE_DIR" TF_JSON
SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-$(tf_out "$TF_JSON" subscription_id)}"
RG="$(tf_out "$TF_JSON" resource_group)"
STORAGE_APP="$(tf_out "$TF_JSON" storage_account_app)"
KV_NAME="$(tf_out "$TF_JSON" key_vault_name)"
DNS_ZONE="$(tf_out "$TF_JSON" dns_zone)"
FD_HOST="$(tf_out "$TF_JSON" front_door_endpoint)"
AKS_NAME="$(tf_out "$TF_JSON" aks_cluster_name)"

az_cli() { run az "$@" ${SUBSCRIPTION_ID:+--subscription "$SUBSCRIPTION_ID"}; }

discover_endpoints() {
  section "Discovering public endpoints"
  VM_IP="$(az_cli vm list-ip-addresses -g "$RG" \
    --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv 2>/dev/null || true)"
  APPGW_IP="$(az_cli network public-ip list -g "$RG" \
    --query "[?contains(name,'appgw')].ipAddress | [0]" -o tsv 2>/dev/null || true)"
  [[ -n "$VM_IP" && "$VM_IP" != "None" ]] && ok "VM ${VM_IP}" || warn "VM IP missing"
  [[ -n "$APPGW_IP" && "$APPGW_IP" != "None" ]] && ok "App Gateway ${APPGW_IP}" || warn "App Gateway IP missing"
  [[ -n "$FD_HOST" && "$FD_HOST" != "null" ]] && ok "Front Door ${FD_HOST}" || warn "Front Door not deployed"
}

gen_http_traffic() {
  section "HTTP traffic (App Gateway, VM, Front Door)"
  local i
  for ((i = 1; i <= ITERATIONS; i++)); do
    [[ -n "${APPGW_IP:-}" && "$APPGW_IP" != "None" ]] && retry_http "http://${APPGW_IP}/" "App Gateway" || true
    [[ -n "${VM_IP:-}" && "$VM_IP" != "None" ]] && retry_http "http://${VM_IP}/" "VM nginx" || true
    [[ -n "$FD_HOST" && "$FD_HOST" != "null" ]] && retry_http "https://${FD_HOST}/" "Front Door" || true
    pause_between
  done
}

gen_storage() {
  section "Storage blob activity"
  [[ -z "$STORAGE_APP" ]] && return
  local container="customer-exports" tmp i blob
  tmp="$(mktemp)"
  echo "ventra,azure,$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$tmp"
  for ((i = 1; i <= ITERATIONS; i++)); do
    blob="traffic/azure-${i}-$(date +%s).csv"
    az_cli storage blob upload --account-name "$STORAGE_APP" --container-name "$container" \
      --name "$blob" --file "$tmp" --auth-mode login --overwrite >/dev/null 2>&1 \
      && ok "blob upload ${blob}" || warn "blob upload"
    az_cli storage blob download --account-name "$STORAGE_APP" --container-name "$container" \
      --name "sample-export.csv" --file /tmp/ventra-azure-sample.csv --auth-mode login >/dev/null 2>&1 \
      && ok "blob download sample-export.csv" || warn "blob download"
    pause_between
  done
  rm -f "$tmp"
}

gen_keyvault() {
  section "Key Vault access (audit events)"
  [[ -z "$KV_NAME" ]] && return
  az_cli keyvault secret show --vault-name "$KV_NAME" --name demo-secret --query id -o tsv >/dev/null 2>&1 \
    && ok "keyvault secret read" || warn "keyvault"
}

gen_dns() {
  section "DNS activity"
  [[ -z "$DNS_ZONE" ]] && return
  az_cli network dns record-set a show -g "$RG" -z "$DNS_ZONE" -n www >/dev/null 2>&1 && ok "dns record show"
  command -v dig >/dev/null 2>&1 && dig +short "www.${DNS_ZONE}" @8.8.8.8 >/dev/null 2>&1 && ok "dig www.${DNS_ZONE}"
}

gen_control_plane() {
  section "Control-plane reads (activity_log, rbac, resource_graph)"
  az_cli group show -n "$RG" >/dev/null 2>&1 && ok "group show"
  az_cli monitor activity-log list --offset 1d --max-events 5 >/dev/null 2>&1 && ok "activity-log list"
  az_cli role assignment list --scope "/subscriptions/${SUBSCRIPTION_ID}" --max-items 5 >/dev/null 2>&1 && ok "role assignments"
  az_cli resource list -g "$RG" >/dev/null 2>&1 && ok "resource list"
  az_cli network watcher flow-log list -l "$LOCATION" >/dev/null 2>&1 && ok "flow-log list" || warn "flow-log list"
}

gen_aks() {
  [[ -z "$AKS_NAME" || "$AKS_NAME" == "null" ]] && return
  section "AKS audit"
  command -v kubectl >/dev/null 2>&1 || { warn "kubectl missing"; return; }
  az_cli aks get-credentials -g "$RG" -n "$AKS_NAME" --overwrite-existing >/dev/null 2>&1 || return
  kubectl get pods -A >/dev/null 2>&1 && ok "kubectl get pods"
}

main() {
  echo -e "${GREEN}Ventra Azure traffic generator${NC} (iterations=${ITERATIONS}, dry_run=${DRY_RUN})"
  discover_endpoints
  gen_http_traffic
  gen_storage
  gen_keyvault
  gen_dns
  gen_control_plane
  gen_aks
  summary_box "Azure" \
    "Edge: AppGW, VM, Front Door HTTP" \
    "Data: blob upload/download" \
    "Control plane: activity log + RBAC reads" \
    "Entra/M365: sign into portal for identity logs"
}
main
