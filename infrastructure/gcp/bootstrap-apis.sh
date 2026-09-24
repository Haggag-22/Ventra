#!/usr/bin/env bash
set -euo pipefail
PROJECT="${1:-${GOOGLE_CLOUD_PROJECT:-${CLOUDSDK_CORE_PROJECT:-}}}"
if [[ -z "${PROJECT}" ]]; then
  echo "Usage: $0 <gcp-project-id>" >&2
  echo "Or set GOOGLE_CLOUD_PROJECT / CLOUDSDK_CORE_PROJECT." >&2
  exit 1
fi
APIS=(
  compute.googleapis.com logging.googleapis.com storage.googleapis.com
  cloudfunctions.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
  run.googleapis.com apigateway.googleapis.com servicecontrol.googleapis.com
  servicemanagement.googleapis.com iam.googleapis.com iamcredentials.googleapis.com
  cloudresourcemanager.googleapis.com monitoring.googleapis.com securitycenter.googleapis.com
  cloudkms.googleapis.com secretmanager.googleapis.com sqladmin.googleapis.com
  bigquery.googleapis.com dns.googleapis.com container.googleapis.com
  serviceusage.googleapis.com
)
gcloud config set project "${PROJECT}"
for ((i=0; i<${#APIS[@]}; i+=20)); do
  batch=("${APIS[@]:i:20}")
  echo "Enabling: ${batch[*]}"
  gcloud services enable "${batch[@]}" --project="${PROJECT}"
done
echo "APIs enabled. Wait 60s then run: ./finish-apply.sh"
