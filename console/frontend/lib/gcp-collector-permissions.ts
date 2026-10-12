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
    label: "Cloud Audit admin",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud Audit system",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud Audit data",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Login events",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Logging posture",
    actions: ["compute.subnetworks.list", "compute.firewalls.list", "logging.sinks.list"],
  },
  {
    label: "VPC flow logs",
    actions: ["logging.logEntries.list", "logging.logs.list", "compute.subnetworks.list"],
  },
  {
    label: "Firewall logs",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud NAT",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Network posture",
    actions: [
      "compute.firewalls.list",
      "compute.networks.list",
      "compute.subnetworks.list",
      "compute.routes.list",
      "compute.packetMirrorings.list",
    ],
  },
  {
    label: "Cloud load balancing",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud CDN",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "API Gateway",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud DNS",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud Armor",
    actions: ["compute.securityPolicies.list", "logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "VM logs",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "GCE and disks",
    actions: ["compute.instances.list", "compute.disks.list", "compute.snapshots.list"],
  },
  {
    label: "Cloud Functions",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "GKE audit",
    actions: ["container.clusters.list", "logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud Storage access",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "BigQuery audit",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Cloud SQL",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Secret Manager",
    actions: ["logging.logEntries.list", "logging.logs.list"],
  },
  {
    label: "Security Command Center",
    actions: ["securitycenter.findings.list"],
  },
  {
    label: "Cloud Monitoring",
    actions: ["logging.logEntries.list", "logging.logs.list", "monitoring.alertPolicies.list"],
  },
  {
    label: "Log export — Cloud Storage",
    actions: ["storage.buckets.get", "storage.objects.get", "storage.objects.list"],
  },
];
