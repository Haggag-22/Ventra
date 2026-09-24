#!/usr/bin/env bash
# Reset ADC and clear stale service-account key env var that overrides login creds.
set -euo pipefail
PROJECT="${1:-${GOOGLE_CLOUD_PROJECT:-${CLOUDSDK_CORE_PROJECT:-}}}"
if [[ -z "${PROJECT}" ]]; then
  echo "Usage: $0 <gcp-project-id>" >&2
  echo "Or set GOOGLE_CLOUD_PROJECT / CLOUDSDK_CORE_PROJECT." >&2
  exit 1
fi
ADC="${HOME}/.config/gcloud/application_default_credentials.json"

if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  echo "WARNING: GOOGLE_APPLICATION_CREDENTIALS is set to:"
  echo "  ${GOOGLE_APPLICATION_CREDENTIALS}"
  echo "That overrides ADC and can point Terraform at the wrong (or deleted) project."
  echo "Unset it in this shell:  unset GOOGLE_APPLICATION_CREDENTIALS"
  echo "Also remove it from ~/.zshrc if exported there."
  echo
fi

if [[ -f "${ADC}" ]]; then
  mv "${ADC}" "${ADC}.bak.$(date +%s)"
  echo "Backed up old ADC"
fi
gcloud config set project "${PROJECT}"
gcloud auth application-default login
gcloud auth application-default set-quota-project "${PROJECT}"
echo
echo "Done. ADC quota project is now ${PROJECT}"
echo "Before terraform apply run:  unset GOOGLE_APPLICATION_CREDENTIALS"
