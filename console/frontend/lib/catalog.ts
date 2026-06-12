// Logs coverage catalog (IR cheat sheet) and collector labels for chips / overview lookups.

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
  sts: "STS activity",
  kms: "KMS",
  secrets: "Secrets Manager",
  ec2: "EC2 / EBS",
  s3: "S3 surface",
  lambda: "Lambda",
};

// AWS — Erblind / IR logs cheat sheet (single list).
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
      { id: "elb_alb_access_logs", label: "ELB/ALB Access Logs", description: "" },
      { id: "route53_resolver_query_logs", label: "Route53 Resolver Query Logs", description: "" },
      { id: "network_firewall_logs", label: "Network Firewall Logs", description: "" },
      { id: "s3_access_logs", label: "S3 Access Logs", description: "" },
      { id: "cloudfront_access_logs", label: "CloudFront Access Logs", description: "" },
      { id: "apigateway_access_logs", label: "API Gateway Access Logs", description: "" },
      { id: "lambda_logs", label: "Lambda Logs", description: "" },
      { id: "opensearch_logs", label: "OpenSearch Logs", description: "" },
      { id: "rds_export_logs", label: "RDS Export Logs", description: "" },
      { id: "dynamodb_streams", label: "DynamoDB Streams", description: "" },
      { id: "guardduty", label: "GuardDuty", description: "" },
      { id: "securityhub", label: "Security Hub", description: "" },
      { id: "detective", label: "Detective", description: "" },
      { id: "inspector2", label: "Inspector2", description: "" },
      { id: "macie", label: "Macie2", description: "" },
      { id: "waf", label: "WAF Logs", description: "" },
      { id: "eks_audit_logs", label: "EKS Audit Logs", description: "" },
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
      { id: "nsg_flow", label: "NSG flow logs", description: "" },
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

export const CLOUD_IMPLEMENTED: Record<Cloud, boolean> = { aws: true, azure: false, gcp: false };

export function catalogItemForId(cloud: Cloud, id: string): CatalogItem | undefined {
  for (const group of CATALOG[cloud] ?? []) {
    const hit = group.items.find((it) => it.id === id);
    if (hit) return hit;
  }
  const extra = EXTRA_COLLECTOR_LABELS[id];
  if (extra) return { id, label: extra, description: "" };
  return undefined;
}
