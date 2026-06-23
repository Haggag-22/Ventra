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
  gcp: {
    storage_access: "Cloud Storage access logs",
    cloud_audit_data: "Cloud Audit data access",
  },
};

export const DATA_ACCESS_COPY: Record<
  Cloud,
  { emptyDescription: string; panelDescription: string; objectNoun: string }
> = {
  aws: {
    emptyDescription:
      "Collectors ran for this window but S3 server access logs and CloudTrail S3 Data Events produced no object-level records. Enable bucket access logging and CloudTrail S3 Data Event selectors, or widen the time window — gaps are recorded in the manifest.",
    panelDescription:
      "Who read or wrote which S3 object, from where — S3 server access logs paired with CloudTrail Data Events. Reads are the exfil lens; writes/deletes are destruction/ransomware.",
    objectNoun: "object",
  },
  azure: {
    emptyDescription:
      "Collectors ran for this window but storage access logs and Key Vault audit events produced no object-level records. Enable blob storage analytics logging and Key Vault diagnostic settings, or widen the time window — gaps are recorded in the manifest.",
    panelDescription:
      "Who read or wrote which blob or secret, from where — Azure Storage access logs paired with Key Vault audit events. Reads are the exfil lens; writes/deletes are destruction or ransomware.",
    objectNoun: "resource",
  },
  gcp: {
    emptyDescription:
      "Collectors ran for this window but Cloud Storage access logs and Cloud Audit data access events produced no object-level records. Enable bucket access logs and Data Access audit logs for storage APIs, or widen the time window — gaps are recorded in the manifest.",
    panelDescription:
      "Who read or wrote which Cloud Storage object, from where — bucket access logs paired with Cloud Audit data access events. Reads are the exfil lens; writes/deletes are destruction or ransomware.",
    objectNoun: "object",
  },
};

export function dataAccessSourceLabel(cloud: Cloud, source: string): string {
  return DATA_ACCESS_SOURCE_LABELS[cloud][source] ?? source;
}
