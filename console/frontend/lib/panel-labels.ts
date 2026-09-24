/** Cloud-specific labels for investigation panels (sidebar, palette, headers). */

import type { Cloud } from "./catalog";

export type NavPanelId =
  | "cloudtrail"
  | "cloudwatch"
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
  cloudwatch: "CloudWatch Logs",
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
    cloudwatch: "CloudWatch Logs",
    "kubernetes-audit": "AKS Audit Logs",
    "data-access": "Storage & Key Vault",
  },
  kubernetes: {
    // The Kubernetes control-plane record is the API-server audit log, so the "cloudtrail"
    // slot is the cluster timeline; the dedicated audit panel keeps the raw audit table.
    cloudtrail: "Cluster Timeline",
    cloudwatch: "Node Logs",
    search: "Security Findings",
    identity: "RBAC & Service Accounts",
    network: "Network Policies & CNI",
    web: "Ingress & Web",
    "kubernetes-audit": "API-Server Audit Logs",
    "data-access": "Secrets & etcd Access",
    collection: "Evidence Coverage",
    resources: "Cluster Inventory",
  },
  gcp: {
    cloudtrail: "Audit Log",
    cloudwatch: "Cloud Logging",
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
