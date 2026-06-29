#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Old SA key env var overrides ADC and breaks every API call.
if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  echo "Unsetting GOOGLE_APPLICATION_CREDENTIALS (was: ${GOOGLE_APPLICATION_CREDENTIALS})"
  unset GOOGLE_APPLICATION_CREDENTIALS
fi

terraform init -upgrade
terraform state list 2>/dev/null | grep '^google_project_service' | while read -r r; do
  echo "Removing stale state: $r"
  terraform state rm "$r"
done
terraform apply
