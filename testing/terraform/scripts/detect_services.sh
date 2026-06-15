#!/usr/bin/env bash
# Read-only probe used by the Terraform `external` data source to discover which
# account/region-singleton detection services are ALREADY enabled. Prints a flat
# JSON object of {service: "enabled"|"disabled"} on stdout. Never exits non-zero
# (an unreachable/forbidden API is treated as "disabled" so apply can proceed).
#
# No jq dependency — region is parsed from the data source's stdin query.

input="$(cat 2>/dev/null || true)"
region="$(printf '%s' "$input" | sed -n 's/.*"region"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -z "$region" ] && region="${AWS_DEFAULT_REGION:-${AWS_REGION:-us-east-1}}"

status_from_text() { # $1=value $2=match -> echo enabled/disabled
  if [ "$1" = "$2" ]; then echo "enabled"; else echo "disabled"; fi
}

# GuardDuty: a detector id means it's on.
gd="$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null || echo None)"
if [ -z "$gd" ] || [ "$gd" = "None" ]; then guardduty="disabled"; else guardduty="enabled"; fi

# Security Hub: describe-hub succeeds only when subscribed.
if aws securityhub describe-hub --region "$region" >/dev/null 2>&1; then
  securityhub="enabled"
else
  securityhub="disabled"
fi

# Macie: session status.
ms="$(aws macie2 get-macie-session --region "$region" --query status --output text 2>/dev/null || echo DISABLED)"
macie="$(status_from_text "$ms" "ENABLED")"

# Detective: any behavior graph means it's on.
dt="$(aws detective list-graphs --region "$region" --query 'GraphList[0].Arn' --output text 2>/dev/null || echo None)"
if [ -z "$dt" ] || [ "$dt" = "None" ]; then detective="disabled"; else detective="enabled"; fi

# Inspector2: account-level state.
ins="$(aws inspector2 batch-get-account-status --region "$region" --query 'accounts[0].state.status' --output text 2>/dev/null || echo DISABLED)"
inspector2="$(status_from_text "$ins" "ENABLED")"

# AWS Config: only one customer-managed configuration recorder allowed per region.
cfg="$(aws configservice describe-configuration-recorders --region "$region" --query 'ConfigurationRecorders[0].name' --output text 2>/dev/null || echo None)"
if [ -z "$cfg" ] || [ "$cfg" = "None" ]; then config="disabled"; else config="enabled"; fi

printf '{"guardduty":"%s","securityhub":"%s","macie":"%s","detective":"%s","inspector2":"%s","config":"%s"}\n' \
  "$guardduty" "$securityhub" "$macie" "$detective" "$inspector2" "$config"
