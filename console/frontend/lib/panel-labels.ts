/** Cloud-specific labels for investigation panels (sidebar, palette, headers). */

import type { Cloud } from "./catalog";

export type NavPanelId =
  | "cloudtrail"
  | "search"
  | "identity"
  | "network"
  | "web"
  | "kubernetes-audit"
  | "data-access"
  | "collection"
  | "resources"
  | "files"
  | "report";

const DEFAULT_LABELS: Record<NavPanelId, string> = {
  cloudtrail: "CloudTrail Timeline",
  search: "Security Findings",
  identity: "Identity & Access",
  network: "Network Activity",
  web: "Web & DNS",
  "kubernetes-audit": "Kubernetes Audit",
  "data-access": "Data Access",
  collection: "Logs Coverage",
  resources: "Resource Inventory",
  files: "Raw Evidence",
  report: "Report",
};

const CLOUD_OVERRIDES: Record<Cloud, Partial<Record<NavPanelId, string>>> = {
  aws: {
    "kubernetes-audit": "EKS Audit Logs",
  },
  azure: {
    cloudtrail: "Activity Log",
    "kubernetes-audit": "AKS Audit Logs",
    "data-access": "Storage & Key Vault",
  },
  gcp: {
    cloudtrail: "Audit Log",
    "kubernetes-audit": "GKE Audit Logs",
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
