// Logs coverage catalog (IR cheat sheet) and collector labels for chips / panel lookups.

import { displayArtifactLabel } from "./artifact-icons";

export interface CatalogItem {
  id: string;
  label: string;
  description: string;
}

export interface CatalogGroup {
  category: string;
  items: CatalogItem[];
}

export const CLOUDS = ["aws", "azure", "gcp", "kubernetes"] as const;
export type Cloud = (typeof CLOUDS)[number];

/**
 * Surfaces Kubernetes as a first-class platform in the console (docs, provider picker,
 * cases, kits, scans). On-prem Kubernetes cases now carry their own investigation panels,
 * Logs Coverage catalog and Resource Inventory roll-ups, so they render as themselves
 * rather than falling back to the AWS layout.
 */
export const KUBERNETES_UI_ENABLED = true;

export function isHiddenUiPlatform(platform: string): boolean {
  return !KUBERNETES_UI_ENABLED && platform.toLowerCase() === "kubernetes";
}

export function isPlatformVisibleInUi(platform: string): boolean {
  return !isHiddenUiPlatform(platform);
}

/**
 * Acquire page platforms (Configuration → Acquire).
 * Full union includes Kubernetes; visible list is gated by `KUBERNETES_UI_ENABLED`.
 */
export const ALL_ACQUIRE_PLATFORMS = ["aws", "azure", "gcp", "kubernetes"] as const;
export type AcquirePlatform = (typeof ALL_ACQUIRE_PLATFORMS)[number];

export const ACQUIRE_PLATFORMS: readonly AcquirePlatform[] = ALL_ACQUIRE_PLATFORMS.filter(
  isPlatformVisibleInUi,
);

/** Full case-platform union (Kubernetes included; hidden when the flag is off). */
export const ALL_CASE_PLATFORMS = [...CLOUDS] as const;
export type CasePlatform = (typeof ALL_CASE_PLATFORMS)[number];

/** Case list tabs — cloud providers, plus Kubernetes when `KUBERNETES_UI_ENABLED`. */
export const CASE_PLATFORMS: readonly CasePlatform[] = ALL_CASE_PLATFORMS.filter(
  isPlatformVisibleInUi,
);

export const CLOUD_LABELS: Record<Cloud, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  kubernetes: "Kubernetes",
};

export const ACQUIRE_PLATFORM_LABELS: Record<AcquirePlatform, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  kubernetes: "Kubernetes",
};

export const CASE_PLATFORM_LABELS: Record<CasePlatform, string> = { ...CLOUD_LABELS };

/** Icon folder under ``public/icons/`` for artifact chips on the Acquire tab. */
export function artifactIconCloud(platform: string): Cloud | "m365" {
  return platform.toLowerCase() === "m365" ? "m365" : (platform.toLowerCase() as Cloud);
}

export function isAcquirePlatform(value: string): value is AcquirePlatform {
  return (ACQUIRE_PLATFORMS as readonly string[]).includes(value.toLowerCase());
}

/** Permission model label for Acquire kit preview (cloud IAM vs Kubernetes RBAC). */
export function acquirePermissionModel(platform: string): "IAM" | "RBAC" {
  return platform.toLowerCase() === "kubernetes" ? "RBAC" : "IAM";
}

/** Labels for inventory / identity collectors not listed on the logs cheat sheet. */
export const EXTRA_COLLECTOR_LABELS: Record<string, string> = {
  account: "Account Context",
  iam: "IAM Snapshot",
  kms: "KMS Key Inventory",
  secrets: "Secrets Manager Inventory",
  ec2: "EC2 / EBS Inventory",
  s3: "S3 Inventory",
  lambda: "Lambda Inventory",
  log_posture: "Logging Posture",
  rbac: "RBAC Snapshot",
  subscription: "Subscription Context",
  entra_directory: "Entra Directory Snapshot",
  resource_graph: "Resource Graph Inventory",
  diag_posture: "Diagnostic Posture",
  vnet_flow: "VNet Flow Logs",
  unified_audit: "M365 Unified Audit Logs",
  unified_audit_search: "M365 Unified Audit Search",
  oauth_consent: "OAuth Consent Grants",
  azure_firewall: "Azure Firewall Logs",
  app_gateway: "App Gateway Access Logs",
  front_door: "Front Door Access Logs",
  dns: "DNS Query Logs",
  storage_access: "Storage Access Logs",
  bigquery_audit: "BigQuery Audit Logs",
  cloud_sql: "Cloud SQL Logs",
  secret_manager: "Secret Manager Access Logs",
  key_vault: "Key Vault Audit Logs",
  aks_audit: "AKS Audit Logs",
  log_analytics: "Log Analytics Diagnostics",
  gce: "GCE Inventory",
  logging_posture: "Logging Posture",
  network_posture: "Network Posture",
  project: "Project Context",
  iam_policy: "IAM Snapshot",
  // On-prem Kubernetes (standalone platform)
  k8s_events: "Kubernetes Events",
  k8s_audit_posture: "Audit logging posture",
  k8s_apiserver_audit: "API-Server Audit Logs",
  k8s_cluster_state: "Cluster inventory",
  k8s_rbac: "RBAC snapshot",
  k8s_container_logs: "Container logs",
  k8s_kubelet_logs: "kubelet / node agent logs",
  k8s_runtime_logs: "CRI Logs",
  k8s_etcd: "Cluster datastore + posture",
  k8s_cni_logs: "CNI plugin logs",
};

// BEGIN GENERATED CATALOG — run: python scripts/generate-catalog-ts.py
// AWS — Erblind / IR logs cheat sheet. Ids match collector source names / posture gap names
// so the Logs Coverage panel can resolve each row straight from the manifest.
const AWS_LOGS: CatalogGroup[] = [
  {
    category: "Logs Checked",
    items: [
      { id: "apigateway", label: "API Gateway Access Logs", description: "" },
      { id: "apigateway", label: "API Gateway Access Logs", description: "" },
      { id: "cloudfront", label: "CloudFront Access Logs", description: "" },
      { id: "cloudtrail", label: "CloudTrail (Management, Data Events, Insights)", description: "" },
      { id: "cloudwatch", label: "CloudWatch Logs events from selected log groups (by name, ARN, or name prefix). Prefer domain collectors (vpc_flow, lambda_logs, eks_audit) when the source service is known; use this for custom or cross-service CloudWatch evidence.", description: "" },
      { id: "config", label: "AWS Config", description: "" },
      { id: "detective", label: "Detective", description: "" },
      { id: "dynamodb_streams", label: "DynamoDB Streams", description: "" },
      { id: "eks_audit", label: "EKS Audit Logs", description: "" },
      { id: "elb_alb", label: "ELB/ALB Access Logs", description: "" },
      { id: "guardduty", label: "GuardDuty", description: "" },
      { id: "inspector2", label: "Inspector2", description: "" },
      { id: "lambda_logs", label: "Lambda Logs", description: "" },
      { id: "lambda_logs", label: "Lambda Logs", description: "" },
      { id: "macie", label: "Macie2", description: "" },
      { id: "network_firewall", label: "Network Firewall Logs", description: "" },
      { id: "opensearch", label: "OpenSearch Logs", description: "" },
      { id: "rds", label: "RDS Export Logs", description: "" },
      { id: "rds", label: "RDS Export Logs", description: "" },
      { id: "route53_resolver", label: "Route53 Resolver Query Logs", description: "" },
      { id: "s3_access", label: "S3 Access Logs", description: "" },
      { id: "securityhub", label: "Security Hub", description: "" },
      { id: "vpc_flow", label: "VPC Flow Logs", description: "" },
      { id: "waf", label: "WAF Logs", description: "" },
    ],
  },
];

const AZURE: CatalogGroup[] = [
  {
    category: "Logs Checked",
    items: [
      { id: "activity_log", label: "Activity Log", description: "" },
      { id: "aks_audit", label: "AKS kube-audit logs", description: "" },
      { id: "app_gateway", label: "Application Gateway / WAF", description: "" },
      { id: "azure_firewall", label: "Azure Firewall logs", description: "" },
      { id: "defender", label: "Defender for Cloud", description: "" },
      { id: "dns", label: "DNS query logs", description: "" },
      { id: "entra_audit", label: "Entra ID audit", description: "" },
      { id: "entra_signin", label: "Entra ID sign-ins", description: "" },
      { id: "front_door", label: "Front Door access / WAF", description: "" },
      { id: "key_vault", label: "Key Vault audit", description: "" },
      { id: "log_analytics", label: "Log Analytics (LA-routed diagnostics)", description: "" },
      { id: "nsg_flow", label: "NSG flow logs", description: "" },
      { id: "oauth_consent", label: "OAuth consent grants", description: "" },
      { id: "storage_access", label: "GCS Access Logs", description: "" },
      { id: "unified_audit", label: "M365 Unified Audit Log", description: "" },
      { id: "unified_audit_search", label: "M365 UAL (Search-UnifiedAuditLog)", description: "" },
      { id: "vnet_flow", label: "VNet flow logs", description: "" },
    ],
  },
];

/** GCP IR cheat sheet — categories mirror the Google Cloud incident response reference. */
const GCP: CatalogGroup[] = [
  {
    category: "DataStorage",
    items: [
      { id: "bigquery_audit", label: "BigQuery Audit Logs", description: "" },
      { id: "cloud_sql", label: "Cloud SQL Logs", description: "" },
      { id: "secret_manager", label: "Secret Manager Access", description: "" },
      { id: "storage_access", label: "GCS Access Logs", description: "" },
    ],
  },
  {
    category: "Detections",
    items: [
      { id: "cloud_monitoring", label: "Cloud Monitoring Alert Logs", description: "" },
      { id: "scc_findings", label: "SCC Findings", description: "" },
    ],
  },
  {
    category: "Identity",
    items: [
      { id: "login_events", label: "Cloud Login Audit Logs", description: "" },
    ],
  },
  {
    category: "ManagementPlane",
    items: [
      { id: "cloud_audit_admin", label: "Admin Activity Audit Logs", description: "" },
      { id: "cloud_audit_data", label: "Data Access Audit Logs", description: "" },
      { id: "cloud_audit_system", label: "System Event Audit Logs", description: "" },
      { id: "logging_posture", label: "Logging Posture", description: "" },
    ],
  },
  {
    category: "Network",
    items: [
      { id: "api_gateway", label: "API Gateway Access Logs", description: "" },
      { id: "cloud_armor", label: "Cloud Armor Logs", description: "" },
      { id: "cloud_cdn", label: "Cloud CDN cache hit/miss, cache fill, and byte-range request logs from HTTP(S) load balancer access logging.", description: "" },
      { id: "cloud_dns", label: "Cloud DNS Logs", description: "" },
      { id: "cloud_nat", label: "Cloud NAT Logs", description: "" },
      { id: "firewall_logs", label: "Firewall Rules Logging", description: "" },
      { id: "load_balancer", label: "Cloud Load Balancing Logs", description: "" },
      { id: "network_posture", label: "Network Posture", description: "" },
      { id: "vpc_flow", label: "VPC Flow Logs", description: "" },
    ],
  },
  {
    category: "Workloads",
    items: [
      { id: "cloud_functions", label: "Cloud Functions Logs", description: "" },
      { id: "gce", label: "GCE Inventory", description: "" },
      { id: "gke_audit", label: "GKE Audit Logs", description: "" },
      { id: "vm_logs", label: "GCE VM Logs", description: "" },
    ],
  },
];

/** On-prem Kubernetes IR cheat sheet — grouped by collection plane and
 *  component (control plane, node, API objects). */
const KUBERNETES: CatalogGroup[] = [
  {
    category: "ClusterState",
    items: [
      { id: "k8s_cluster_state", label: "Cluster Inventory", description: "" },
      { id: "k8s_rbac", label: "RBAC Snapshot", description: "" },
    ],
  },
  {
    category: "Audit",
    items: [
      { id: "k8s_apiserver_audit", label: "API-Server Audit Log", description: "" },
      { id: "k8s_audit_posture", label: "Audit Logging Posture", description: "" },
      { id: "k8s_events", label: "Kubernetes Events", description: "" },
    ],
  },
  {
    category: "Node",
    items: [
      { id: "k8s_container_logs", label: "Container Logs", description: "" },
      { id: "k8s_cni_logs", label: "CNI Plugin Logs", description: "" },
      { id: "k8s_etcd", label: "Cluster Datastore (etcd / sqlite) + Posture", description: "" },
      { id: "k8s_kubelet_logs", label: "Kubelet / Node Agent Logs", description: "" },
      { id: "k8s_runtime_logs", label: "CRI Logs", description: "" },
    ],
  },
];
// END GENERATED CATALOG

export const CATALOG: Record<Cloud, CatalogGroup[]> = {
  aws: AWS_LOGS,
  azure: AZURE,
  gcp: GCP,
  kubernetes: KUBERNETES,
};

export const CLOUD_IMPLEMENTED: Record<Cloud, boolean> = {
  aws: true,
  azure: true,
  gcp: true,
  kubernetes: true,
};

/** Acquire page category display order — Identity first, Management Plane second, then detections / IR workflow. */
export const COLLECTOR_CATEGORY_ORDER = [
  "Identity",
  "ManagementPlane",
  "Detections",
  "Network",
  "DataStorage",
  // On-prem Kubernetes: inventory/identity first, then audit trail, then node evidence
  "ClusterState",
  "Audit",
  "Workloads",
  "Node",
] as const;

export function compareCollectorCategories(a: string, b: string): number {
  const rank = (category: string) => {
    const idx = (COLLECTOR_CATEGORY_ORDER as readonly string[]).indexOf(category);
    return idx === -1 ? COLLECTOR_CATEGORY_ORDER.length : idx;
  };
  const diff = rank(a) - rank(b);
  return diff !== 0 ? diff : a.localeCompare(b);
}

export function catalogItemForId(cloud: Cloud, id: string): CatalogItem | undefined {
  for (const group of CATALOG[cloud] ?? []) {
    const hit = group.items.find((it) => it.id === id);
    if (hit) return { ...hit, label: displayArtifactLabel(id, cloud) };
  }
  if (EXTRA_COLLECTOR_LABELS[id]) {
    return { id, label: displayArtifactLabel(id, cloud), description: "" };
  }
  return undefined;
}
