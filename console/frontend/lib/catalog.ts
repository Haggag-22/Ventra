// Logs coverage catalog (IR cheat sheet) and collector labels for chips / panel lookups.

export interface CatalogItem {
  id: string;
  label: string;
  description: string;
}

export interface CatalogGroup {
  category: string;
  items: CatalogItem[];
}

export const CLOUDS = ["aws", "azure", "gcp"] as const;
export type Cloud = (typeof CLOUDS)[number];

/** Case list tabs — cloud providers plus standalone Kubernetes packages (roadmap). */
export const CASE_PLATFORMS = [...CLOUDS, "kubernetes"] as const;
export type CasePlatform = (typeof CASE_PLATFORMS)[number];

export const CLOUD_LABELS: Record<Cloud, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
};

export const CASE_PLATFORM_LABELS: Record<CasePlatform, string> = {
  ...CLOUD_LABELS,
  kubernetes: "Kubernetes",
};

/** Labels for inventory / identity collectors not listed on the logs cheat sheet. */
export const EXTRA_COLLECTOR_LABELS: Record<string, string> = {
  account: "Account context",
  iam: "IAM snapshot",
  kms: "KMS",
  secrets: "Secrets Manager",
  ec2: "EC2 / EBS",
  s3: "S3 surface",
  lambda: "Lambda",
  log_posture: "Logging posture",
  rbac: "Azure RBAC",
  subscription: "Subscription context",
  entra_directory: "Entra directory",
  resource_graph: "Resource Graph inventory",
  diag_posture: "Diagnostic posture",
  vnet_flow: "VNet flow logs",
  unified_audit: "M365 Unified Audit",
  unified_audit_search: "M365 UAL (Search)",
  oauth_consent: "OAuth consent grants",
  azure_firewall: "Azure Firewall",
  app_gateway: "Application Gateway",
  front_door: "Front Door",
  dns: "DNS query logs",
  storage_access: "GCS access logs",
  bigquery_audit: "BigQuery audit logs",
  cloud_sql: "Cloud SQL logs",
  secret_manager: "Secret Manager access",
  key_vault: "Key Vault audit",
  aks_audit: "AKS audit logs",
  log_analytics: "Log Analytics diagnostics",
  gce: "GCE / persistent disks",
  logging_posture: "Logging posture",
  network_posture: "Network posture",
  project: "Project context",
  iam_policy: "IAM snapshot",
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
      { id: "cloud_dns", label: "Cloud DNS Logs", description: "" },
      { id: "cloud_nat", label: "Cloud NAT Logs", description: "" },
      { id: "firewall_logs", label: "Firewall Rules Logging", description: "" },
      { id: "load_balancer", label: "Load Balancer Access Logs", description: "" },
      { id: "cloud_cdn", label: "Cloud CDN Access Logs", description: "" },
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
// END GENERATED CATALOG

export const CATALOG: Record<Cloud, CatalogGroup[]> = {
  aws: AWS_LOGS,
  azure: AZURE,
  gcp: GCP,
};

export const CLOUD_IMPLEMENTED: Record<Cloud, boolean> = { aws: true, azure: true, gcp: true };

/** Acquire page category display order — Identity first, Detections second, then IR workflow order. */
export const COLLECTOR_CATEGORY_ORDER = [
  "Identity",
  "Detections",
  "ManagementPlane",
  "Network",
  "DataStorage",
  "Workloads",
  "M365",
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
    if (hit) return hit;
  }
  const extra = EXTRA_COLLECTOR_LABELS[id];
  if (extra) return { id, label: extra, description: "" };
  return undefined;
}
