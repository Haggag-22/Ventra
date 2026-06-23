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
  storage_access: "Storage access logs",
  key_vault: "Key Vault audit",
  aks_audit: "AKS audit logs",
  log_analytics: "Log Analytics diagnostics",
  project: "Project context",
  iam_policy: "IAM policy bindings",
};

// BEGIN GENERATED CATALOG — run: python scripts/generate-catalog-ts.py
// AWS — Erblind / IR logs cheat sheet. Ids match collector source names / posture gap names
// so the Logs Coverage panel can resolve each row straight from the manifest.
const AWS_LOGS: CatalogGroup[] = [
  {
    category: "Logs Checked",
    items: [
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
      { id: "macie", label: "Macie2", description: "" },
      { id: "network_firewall", label: "Network Firewall Logs", description: "" },
      { id: "opensearch", label: "OpenSearch Logs", description: "" },
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
      { id: "storage_access", label: "Storage access logs", description: "" },
      { id: "unified_audit", label: "M365 Unified Audit Log", description: "" },
      { id: "unified_audit_search", label: "M365 UAL (Search-UnifiedAuditLog)", description: "" },
      { id: "vnet_flow", label: "VNet flow logs", description: "" },
    ],
  },
];

/** GCP IR cheat sheet — categories mirror the Google Cloud incident response reference. */
const GCP: CatalogGroup[] = [
  {
    category: "Detections",
    items: [
      { id: "cloud_monitoring", label: "Cloud Monitoring Alerts", description: "" },
      { id: "scc_findings", label: "Security Command Center", description: "" },
    ],
  },
  {
    category: "Identity",
    items: [
      { id: "login_events", label: "Login Audit Logs", description: "" },
      { id: "workspace_audit", label: "Workspace Group Audit Logs", description: "" },
    ],
  },
  {
    category: "ManagementPlane",
    items: [
      { id: "cloud_audit_admin", label: "Admin Activity Logs", description: "" },
      { id: "cloud_audit_data", label: "Data Access Logs", description: "" },
      { id: "cloud_audit_system", label: "System Event Logs", description: "" },
    ],
  },
  {
    category: "Network",
    items: [
      { id: "api_gateway", label: "API Gateway Logs", description: "" },
      { id: "firewall_logs", label: "VPC Firewall Logs", description: "" },
      { id: "load_balancer", label: "Cloud Load Balancer Logs", description: "" },
      { id: "vpc_flow", label: "VPC Flow Logs", description: "" },
    ],
  },
  {
    category: "Workloads",
    items: [
      { id: "cloud_functions", label: "Cloud Functions Logs", description: "" },
      { id: "storage_access", label: "Storage access logs", description: "" },
      { id: "vm_logs", label: "Compute Engine VM Logs", description: "" },
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

export function catalogItemForId(cloud: Cloud, id: string): CatalogItem | undefined {
  for (const group of CATALOG[cloud] ?? []) {
    const hit = group.items.find((it) => it.id === id);
    if (hit) return hit;
  }
  const extra = EXTRA_COLLECTOR_LABELS[id];
  if (extra) return { id, label: extra, description: "" };
  return undefined;
}
