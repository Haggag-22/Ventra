// The catalog of collectible artifacts per cloud. The Collection panel cross-references this
// against what a case's manifest actually reported, so an analyst sees not just what WAS
// collected but everything that COULD be — and exactly what's missing and why.

export interface CatalogItem {
  id: string; // logical source name (matches manifest source names)
  label: string;
  description: string;
  tier: 1 | 2 | 3;
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

// AWS — implemented (Tier 1 baseline + Tier 2/3).
const AWS: CatalogGroup[] = [
  {
    category: "Identity & Access",
    items: [
      { id: "account", label: "Account context", description: "Account, org, regions, operator identity", tier: 1 },
      { id: "iam", label: "IAM snapshot", description: "Users, roles, policies, keys, credential report", tier: 1 },
      { id: "sts", label: "STS activity", description: "AssumeRole events (filtered from CloudTrail LookupEvents)", tier: 1 },
      { id: "kms", label: "KMS", description: "Key inventory, policies, grants", tier: 2 },
      { id: "secrets", label: "Secrets Manager", description: "Secret metadata (never values)", tier: 2 },
    ],
  },
  {
    category: "Control Plane",
    items: [
      { id: "cloudtrail", label: "CloudTrail", description: "Management, insight, data, and network-activity events + trail config", tier: 1 },
      { id: "config", label: "AWS Config", description: "Recorder state + compliance findings", tier: 2 },
    ],
  },
  {
    category: "Network",
    items: [
      { id: "vpc_flow", label: "VPC Flow Logs", description: "Flow-log config + recent records", tier: 1 },
      { id: "waf", label: "AWS WAF", description: "Web ACL configs, logging, sampled requests", tier: 1 },
    ],
  },
  {
    category: "Threat Detection",
    items: [
      { id: "guardduty", label: "GuardDuty", description: "Findings, detector config, suppression filters", tier: 1 },
      { id: "securityhub", label: "Security Hub", description: "Aggregated ASFF findings + standards", tier: 2 },
      { id: "macie", label: "Macie", description: "Sensitive-data and policy findings", tier: 2 },
      { id: "detective", label: "Detective", description: "Graph membership and open investigations", tier: 2 },
    ],
  },
  {
    category: "Workloads & Storage",
    items: [
      { id: "ec2", label: "EC2 / EBS", description: "Inventory + snapshot share/copy evidence trail", tier: 2 },
      { id: "s3", label: "S3 surface", description: "Bucket inventory, exposure, logging, Object Lock", tier: 2 },
      { id: "lambda", label: "Lambda", description: "Function inventory + resource policies", tier: 2 },
    ],
  },
];

// Azure — planned (Phase 6). Listed so the Collection tab is meaningful pre-implementation.
const AZURE: CatalogGroup[] = [
  {
    category: "Identity & Access",
    items: [
      { id: "entra_signin", label: "Entra ID sign-ins", description: "Microsoft Entra ID sign-in logs", tier: 1 },
      { id: "entra_audit", label: "Entra ID audit", description: "Directory change audit logs", tier: 1 },
      { id: "rbac", label: "Azure RBAC", description: "Role assignments & definitions", tier: 1 },
    ],
  },
  {
    category: "Control Plane",
    items: [
      { id: "activity_log", label: "Activity Log", description: "Subscription control-plane operations", tier: 1 },
    ],
  },
  {
    category: "Network",
    items: [
      { id: "nsg_flow", label: "NSG flow logs", description: "Network security group flow logs", tier: 1 },
    ],
  },
  {
    category: "Threat Detection",
    items: [
      { id: "defender", label: "Defender for Cloud", description: "Microsoft Defender alerts", tier: 1 },
    ],
  },
];

// GCP — planned (Phase 7).
const GCP: CatalogGroup[] = [
  {
    category: "Identity & Access",
    items: [
      { id: "iam_policy", label: "IAM policy", description: "Policy bindings & service accounts", tier: 1 },
      { id: "login_events", label: "Login events", description: "Workspace / Cloud Identity logins", tier: 1 },
    ],
  },
  {
    category: "Control Plane",
    items: [
      { id: "cloud_audit_admin", label: "Audit: Admin Activity", description: "Cloud Audit Logs — admin activity", tier: 1 },
      { id: "cloud_audit_data", label: "Audit: Data Access", description: "Cloud Audit Logs — data access", tier: 1 },
    ],
  },
  {
    category: "Network",
    items: [{ id: "vpc_flow", label: "VPC Flow Logs", description: "VPC flow logs", tier: 1 }],
  },
  {
    category: "Threat Detection",
    items: [{ id: "scc_findings", label: "Security Command Center", description: "SCC findings", tier: 1 }],
  },
];

export const CATALOG: Record<Cloud, CatalogGroup[]> = { aws: AWS, azure: AZURE, gcp: GCP };

export const CLOUD_IMPLEMENTED: Record<Cloud, boolean> = { aws: true, azure: false, gcp: false };
