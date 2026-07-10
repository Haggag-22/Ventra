/** Read-only IAM actions Ventra needs for GCP connection test and collection. */

export type GcpPermissionGroup = {
  label: string;
  actions: string[];
};

/** Minimum action required to validate a GCP connection. */
export const GCP_AUTH_PERMISSION_GROUP: GcpPermissionGroup = {
  label: "Authentication",
  actions: ["resourcemanager.projects.get"],
};

/** Grouped collector permissions — sourced from docs/iam-policies/gcp-collector-permissions.txt */
export const GCP_COLLECTOR_PERMISSION_GROUPS: GcpPermissionGroup[] = [
  {
    label: "Project snapshot",
    actions: ["resourcemanager.projects.get"],
  },
  {
    label: "IAM snapshot",
    actions: [
      "resourcemanager.projects.getIamPolicy",
      "iam.serviceAccounts.list",
      "iam.serviceAccounts.getIamPolicy",
      "iam.serviceAccountKeys.list",
      "iam.roles.list",
    ],
  },
  {
    label: "Cloud Logging",
    actions: ["logging.logEntries.list", "logging.sinks.list"],
  },
  {
    label: "Compute & network",
    actions: [
      "compute.instances.list",
      "compute.disks.list",
      "compute.snapshots.list",
      "compute.firewalls.list",
      "compute.networks.list",
      "compute.subnetworks.list",
      "compute.routes.list",
      "compute.packetMirrorings.list",
      "compute.securityPolicies.list",
    ],
  },
  {
    label: "GKE & containers",
    actions: ["container.clusters.list"],
  },
  {
    label: "Security Command Center",
    actions: ["securitycenter.findings.list"],
  },
  {
    label: "Monitoring",
    actions: ["monitoring.alertPolicies.list"],
  },
  {
    label: "Log export — Cloud Storage",
    actions: ["storage.buckets.get", "storage.objects.get", "storage.objects.list"],
  },
];
