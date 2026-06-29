import type { Cloud } from "@/lib/catalog";

/** Display filename stems under ``public/icons/<cloud>/`` (must match extract-artifact-icons). */
export const ARTIFACT_ICON_LABELS: Record<string, string> = {
  account: "account",
  apigateway: "api gateway access logs",
  cloudfront: "cloudfront access logs",
  cloudtrail: "cloudtrail",
  config: "config",
  detective: "detective",
  ec2: "ec2",
  eks_audit: "eks audit",
  elb_alb: "elb alb access logs",
  guardduty: "guardduty",
  iam: "iam",
  inspector2: "inspector2",
  kms: "kms",
  lambda: "lambda",
  lambda_logs: "lambda logs",
  log_posture: "log posture",
  macie: "macie",
  route53_resolver: "route53 resolver",
  rds: "rds logs",
  s3: "s3",
  s3_access: "s3 access logs",
  secrets: "secrets",
  securityhub: "security hub",
  vpc_flow: "vpc flow logs",
  waf: "waf",
  activity_log: "activity log",
  aks_audit: "aks audit",
  app_gateway: "app gateway access logs",
  azure_firewall: "azure firewall logs",
  defender: "defender",
  diag_posture: "diagnostic posture",
  dns: "dns",
  entra_audit: "entra audit",
  entra_directory: "entra directory",
  entra_signin: "entra signin",
  front_door: "front door access logs",
  key_vault: "key vault",
  log_analytics: "log analytics",
  nsg_flow: "nsg flow logs",
  oauth_consent: "oauth consent",
  rbac: "rbac",
  resource_graph: "resource graph",
  storage_access: "storage access logs",
  bigquery_audit: "bigquery audit",
  cloud_sql: "cloud sql",
  secret_manager: "secret manager",
  subscription: "subscription",
  unified_audit: "unified audit",
  unified_audit_search: "unified audit search",
  vnet_flow: "vnet flow logs",
  api_gateway: "api gateway",
  cloud_audit_admin: "cloud audit admin",
  cloud_audit_data: "cloud audit data",
  cloud_audit_system: "cloud audit system",
  cloud_functions: "cloud functions",
  cloud_monitoring: "cloud monitoring",
  firewall_logs: "firewall logs",
  gce: "compute engine",
  iam_policy: "iam policy",
  load_balancer: "load balancer access logs",
  logging_posture: "logging posture",
  login_events: "login events",
  network_posture: "network posture",
  project: "project",
  scc_findings: "scc findings",
  vm_logs: "vm logs",
  gke_audit: "gke audit",
  cloud_dns: "cloud dns",
  cloud_armor: "cloud armor",
  cloud_nat: "cloud nat",
};

/** Per-cloud icon filename overrides when the default label differs by provider. */
const CLOUD_ARTIFACT_ICON_LABELS: Partial<Record<Cloud, Record<string, string>>> = {
  aws: {
    storage_access: "s3 access logs",
  },
  azure: {
    storage_access: "storage access logs",
  },
  gcp: {
    storage_access: "gcs access logs",
  },
};

/** UI display names (proper product / acronym casing). Icon filenames stay lowercase in ``ARTIFACT_ICON_LABELS``. */
const ARTIFACT_DISPLAY_LABELS: Record<string, string> = {
  account: "Account",
  apigateway: "API Gateway Access Logs",
  cloudfront: "CloudFront Access Logs",
  cloudtrail: "CloudTrail",
  config: "Config",
  detective: "Detective",
  ec2: "EC2",
  eks_audit: "EKS Audit",
  elb_alb: "ELB/ALB Access Logs",
  guardduty: "GuardDuty",
  iam: "IAM",
  inspector2: "Inspector",
  kms: "KMS",
  lambda: "Lambda",
  lambda_logs: "Lambda Logs",
  log_posture: "Log Posture",
  macie: "Macie",
  route53_resolver: "Route53 Resolver",
  rds: "RDS Export Logs",
  s3: "S3",
  s3_access: "S3 Access Logs",
  secrets: "Secrets Manager",
  securityhub: "Security Hub",
  vpc_flow: "VPC Flow Logs",
  waf: "WAF",
  activity_log: "Activity Log",
  aks_audit: "AKS Audit",
  app_gateway: "App Gateway Access Logs",
  azure_firewall: "Azure Firewall Logs",
  defender: "Defender for Cloud",
  diag_posture: "Diagnostic Posture",
  dns: "DNS",
  entra_audit: "Entra Audit",
  entra_directory: "Entra Directory",
  entra_signin: "Entra Sign-in",
  front_door: "Front Door Access Logs",
  key_vault: "Key Vault",
  log_analytics: "Log Analytics",
  nsg_flow: "NSG Flow Logs",
  oauth_consent: "OAuth Consent",
  rbac: "RBAC",
  resource_graph: "Resource Graph",
  storage_access: "GCS Access Logs",
  bigquery_audit: "BigQuery Audit Logs",
  cloud_sql: "Cloud SQL Logs",
  secret_manager: "Secret Manager Access",
  subscription: "Subscription",
  unified_audit: "Unified Audit",
  unified_audit_search: "Unified Audit Search",
  vnet_flow: "VNet Flow Logs",
  api_gateway: "API Gateway Access Logs",
  cloud_audit_admin: "Admin Activity Audit Logs",
  cloud_audit_data: "Data Access Audit Logs",
  cloud_audit_system: "System Event Audit Logs",
  cloud_functions: "Cloud Functions Logs",
  cloud_monitoring: "Cloud Monitoring Alert Logs",
  firewall_logs: "Firewall Rules Logging",
  gce: "GCE Inventory",
  iam_policy: "IAM Snapshot",
  load_balancer: "Load Balancer Access Logs",
  logging_posture: "Logging Posture",
  login_events: "Cloud Login Audit Logs",
  network_posture: "Network Posture",
  project: "Project Context",
  scc_findings: "SCC Findings",
  vm_logs: "GCE VM Logs",
  gke_audit: "GKE Audit Logs",
  cloud_dns: "Cloud DNS Logs",
  cloud_armor: "Cloud Armor Logs",
  cloud_nat: "Cloud NAT Logs",
};

export function displayArtifactLabel(collector: string): string {
  if (ARTIFACT_DISPLAY_LABELS[collector]) return ARTIFACT_DISPLAY_LABELS[collector];
  const label = ARTIFACT_ICON_LABELS[collector] ?? collector.replace(/_/g, " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function iconExtension(cloud: Cloud): string {
  return cloud === "azure" ? ".svg" : ".png";
}

export function resolveArtifactIconLabel(cloud: string, collector: string): string | null {
  const c = cloud.toLowerCase() as Cloud;
  const cloudLabel = CLOUD_ARTIFACT_ICON_LABELS[c]?.[collector];
  if (cloudLabel) return cloudLabel;
  return ARTIFACT_ICON_LABELS[collector] ?? null;
}

export function artifactIconSrc(cloud: string, collector: string): string | null {
  const label = resolveArtifactIconLabel(cloud, collector);
  if (!label) return null;
  const c = cloud.toLowerCase() as Cloud;
  return `/icons/${c}/${encodeURIComponent(label)}${iconExtension(c)}`;
}
