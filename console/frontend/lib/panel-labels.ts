/** Cloud-specific labels for investigation panels (sidebar, palette, headers). */

import type { Cloud } from "./catalog";

export type NavPanelId =
  | "cloudtrail"
  | "search"
  | "identity"
  | "network"
  | "web"
  | "data-access"
  | "collection"
  | "resources"
  | "report"
  | "timeline";

const DEFAULT_LABELS: Record<NavPanelId, string> = {
  timeline: "Timeline",
  cloudtrail: "CloudTrail Timeline",
  search: "Security Findings",
  identity: "Identity & Access",
  network: "Network Activity",
  web: "Web & DNS",
  "data-access": "Data Access",
  collection: "Logs Coverage",
  resources: "Resource Inventory",
  report: "Report",
};

const CLOUD_OVERRIDES: Record<Cloud, Partial<Record<NavPanelId, string>>> = {
  aws: {},
  azure: {
    cloudtrail: "Activity Log Timeline",
  },
  gcp: {
    cloudtrail: "Audit Log Timeline",
    search: "Security Command Center",
    identity: "Identity & IAM",
    network: "VPC & Firewall",
    web: "Load Balancer & API Gateway",
    "data-access": "Storage Access",
  },
};

export function panelLabel(cloud: Cloud, panel: NavPanelId): string {
  return CLOUD_OVERRIDES[cloud]?.[panel] ?? DEFAULT_LABELS[panel];
}
