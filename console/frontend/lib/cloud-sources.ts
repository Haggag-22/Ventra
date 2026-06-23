/** Cloud-specific event source lists for investigation panels. */

import type { Cloud } from "./catalog";

export const CONTROL_PLANE_SOURCES: Record<Cloud, string[]> = {
  aws: ["cloudtrail"],
  azure: ["activity_log", "entra_signin", "entra_audit", "unified_audit", "unified_audit_search", "oauth_consent"],
  gcp: [
    "cloud_audit_admin",
    "cloud_audit_system",
    "cloud_audit_data",
    "login_events",
    "workspace_audit",
  ],
};

export const FLOW_SOURCES: Record<Cloud, string[]> = {
  aws: ["vpc_flow"],
  azure: ["vnet_flow", "nsg_flow", "azure_firewall"],
  gcp: ["vpc_flow", "firewall_logs"],
};

export const FINDING_SOURCES: Record<Cloud, string[]> = {
  aws: ["guardduty", "securityhub", "inspector2", "macie", "detective"],
  azure: ["defender"],
  gcp: ["scc_findings", "cloud_monitoring"],
};

export const WEB_SOURCES: Record<Cloud, string[]> = {
  aws: ["elb_alb", "cloudfront", "waf", "route53_resolver"],
  azure: ["app_gateway", "front_door", "dns", "log_analytics"],
  gcp: ["load_balancer", "api_gateway"],
};

export const DATA_ACCESS_SOURCES: Record<Cloud, string[]> = {
  aws: ["s3_access", "cloudtrail"],
  azure: ["storage_access", "key_vault", "log_analytics"],
  gcp: ["storage_access", "cloud_audit_data"],
};

/** Kubernetes API audit logs — EKS, AKS, and (future) GKE collectors. */
export const KUBERNETES_AUDIT_SOURCES: Record<Cloud, string[]> = {
  aws: ["eks_audit"],
  azure: ["aks_audit"],
  gcp: ["gke_audit"],
};

export function controlPlaneSources(cloud: Cloud): string[] {
  return CONTROL_PLANE_SOURCES[cloud] ?? CONTROL_PLANE_SOURCES.aws;
}

export function flowSources(cloud: Cloud): string[] {
  return FLOW_SOURCES[cloud] ?? FLOW_SOURCES.aws;
}

export function findingSources(cloud: Cloud): string[] {
  return FINDING_SOURCES[cloud] ?? FINDING_SOURCES.aws;
}

export function webSources(cloud: Cloud): string[] {
  return WEB_SOURCES[cloud] ?? WEB_SOURCES.aws;
}

export function dataAccessSources(cloud: Cloud): string[] {
  return DATA_ACCESS_SOURCES[cloud] ?? DATA_ACCESS_SOURCES.aws;
}

export function kubernetesAuditSources(cloud: Cloud): string[] {
  return KUBERNETES_AUDIT_SOURCES[cloud] ?? KUBERNETES_AUDIT_SOURCES.aws;
}

export function caseCloud(manifestCloud?: string | null): Cloud {
  if (manifestCloud === "azure" || manifestCloud === "gcp") return manifestCloud;
  return "aws";
}
