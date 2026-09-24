/** Cloud-specific labels and copy for the Data Access panel. */

import type { Cloud } from "./catalog";

export const DATA_ACCESS_SOURCE_LABELS: Record<Cloud, Record<string, string>> = {
  aws: {
    s3_access: "S3 server access logs",
    cloudtrail: "CloudTrail Data Events",
  },
  azure: {
    storage_access: "Storage access logs",
    key_vault: "Key Vault audit",
    log_analytics: "Log Analytics",
  },
  kubernetes: {
    k8s_apiserver_audit: "API-Server Audit Logs (Secret reads)",
    k8s_etcd: "etcd access and at-rest posture",
  },
  gcp: {
  storage_access: "GCS access logs",
  bigquery_audit: "BigQuery data access audit",
  cloud_sql: "Cloud SQL query and connection logs",
  secret_manager: "Secret Manager access audit",
  cloud_audit_data: "Cloud Audit data access",
  },
};

export const DATA_ACCESS_COPY: Record<
  Cloud,
  { emptyDescription: string; objectNoun: string }
> = {
  aws: {
    emptyDescription:
      "Collectors ran for this window but S3 server access logs and CloudTrail S3 Data Events produced no object-level records. Enable bucket access logging and CloudTrail S3 Data Event selectors, or widen the time window — gaps are recorded in the manifest.",
    objectNoun: "object",
  },
  azure: {
    emptyDescription:
      "Collectors ran for this window but storage access logs and Key Vault audit events produced no object-level records. Enable blob storage analytics logging and Key Vault diagnostic settings, or widen the time window — gaps are recorded in the manifest.",
    objectNoun: "resource",
  },
  gcp: {
    emptyDescription:
      "Collectors ran for this window but GCS access logs, BigQuery audit, Cloud SQL logs, and Secret Manager access events produced no object-level records. Enable bucket access logs, Data Access audit logs for storage and secret APIs, and Cloud SQL logging export, or widen the time window — gaps are recorded in the manifest.",
    objectNoun: "object",
  },
  kubernetes: {
    emptyDescription:
      "In a cluster, data access means Secret reads — and the only record of them is the API-server audit log. No Secret access was found for this window: either the audit policy does not log 'secrets' (check Audit Logging Posture), the audit log does not reach back this far, or nothing read a Secret. Gaps are recorded in the manifest.",
    objectNoun: "secret",
  },
};

export function dataAccessSourceLabel(cloud: Cloud, source: string): string {
  return DATA_ACCESS_SOURCE_LABELS[cloud]?.[source] ?? source;
}
