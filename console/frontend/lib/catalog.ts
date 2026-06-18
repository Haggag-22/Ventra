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

export const CLOUD_LABELS: Record<Cloud, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
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
};

// AWS — Erblind / IR logs cheat sheet. Ids match collector source names / posture gap names
// so the Logs Coverage panel can resolve each row straight from the manifest.
const AWS_LOGS: CatalogGroup[] = [
  {
    category: "Logs Checked",
    items: [
      {
        id: "cloudtrail",
        label: "CloudTrail (Management, Data Events, Insights)",
        description: "",
      },
      { id: "config", label: "AWS Config", description: "" },
      { id: "vpc_flow", label: "VPC Flow Logs", description: "" },
      { id: "elb_alb", label: "ELB/ALB Access Logs", description: "" },
      { id: "route53_resolver", label: "Route53 Resolver Query Logs", description: "" },
      { id: "network_firewall", label: "Network Firewall Logs", description: "" },
      { id: "s3_access", label: "S3 Access Logs", description: "" },
      { id: "cloudfront", label: "CloudFront Access Logs", description: "" },
      { id: "apigateway", label: "API Gateway Access Logs", description: "" },
      { id: "lambda_logs", label: "Lambda Logs", description: "" },
      { id: "opensearch", label: "OpenSearch Logs", description: "" },
      { id: "rds", label: "RDS Export Logs", description: "" },
      { id: "dynamodb_streams", label: "DynamoDB Streams", description: "" },
      { id: "guardduty", label: "GuardDuty", description: "" },
      { id: "securityhub", label: "Security Hub", description: "" },
      { id: "detective", label: "Detective", description: "" },
      { id: "inspector2", label: "Inspector2", description: "" },
      { id: "macie", label: "Macie2", description: "" },
      { id: "waf", label: "WAF Logs", description: "" },
      { id: "eks_audit", label: "EKS Audit Logs", description: "" },
    ],
  },
];

const AZURE: CatalogGroup[] = [
  {
    category: "Logs Checked",
    items: [
      { id: "entra_signin", label: "Entra ID sign-ins", description: "" },
      { id: "entra_audit", label: "Entra ID audit", description: "" },
      { id: "activity_log", label: "Activity Log", description: "" },
      { id: "unified_audit", label: "M365 Unified Audit Log", description: "" },
      { id: "unified_audit_search", label: "M365 UAL (Search-UnifiedAuditLog)", description: "" },
      { id: "oauth_consent", label: "OAuth consent grants", description: "" },
      { id: "vnet_flow", label: "VNet flow logs", description: "" },
      { id: "nsg_flow", label: "NSG flow logs", description: "" },
      { id: "azure_firewall", label: "Azure Firewall logs", description: "" },
      { id: "app_gateway", label: "Application Gateway / WAF", description: "" },
      { id: "front_door", label: "Front Door access / WAF", description: "" },
      { id: "dns", label: "DNS query logs", description: "" },
      { id: "storage_access", label: "Storage access logs", description: "" },
      { id: "key_vault", label: "Key Vault audit", description: "" },
      { id: "aks_audit", label: "AKS kube-audit logs", description: "" },
      { id: "log_analytics", label: "Log Analytics (LA-routed diagnostics)", description: "" },
      { id: "defender", label: "Defender for Cloud", description: "" },
    ],
  },
];

const GCP: CatalogGroup[] = [
  {
    category: "Logs Checked",
    items: [
      { id: "cloud_audit_admin", label: "Audit: Admin Activity", description: "" },
      { id: "cloud_audit_data", label: "Audit: Data Access", description: "" },
      { id: "vpc_flow", label: "VPC Flow Logs", description: "" },
      { id: "scc_findings", label: "Security Command Center", description: "" },
    ],
  },
];

export const CATALOG: Record<Cloud, CatalogGroup[]> = {
  aws: AWS_LOGS,
  azure: AZURE,
  gcp: GCP,
};

export const CLOUD_IMPLEMENTED: Record<Cloud, boolean> = { aws: true, azure: true, gcp: false };

export function catalogItemForId(cloud: Cloud, id: string): CatalogItem | undefined {
  for (const group of CATALOG[cloud] ?? []) {
    const hit = group.items.find((it) => it.id === id);
    if (hit) return hit;
  }
  const extra = EXTRA_COLLECTOR_LABELS[id];
  if (extra) return { id, label: extra, description: "" };
  return undefined;
}
