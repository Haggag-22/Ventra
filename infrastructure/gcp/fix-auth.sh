#!/usr/bin/env bash
# Reset ADC and clear stale service-account key env var that overrides login creds.
set -euo pipefail
PROJECT="${1:-ultimate-opus-500916-b2}"
ADC="${HOME}/.config/gcloud/application_default_credentials.json"

if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  echo "WARNING: GOOGLE_APPLICATION_CREDENTIALS is set to:"
  echo "  ${GOOGLE_APPLICATION_CREDENTIALS}"
  echo "That overrides ADC and causes 'Project #621232171576 has been deleted' errors."
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
