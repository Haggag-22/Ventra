/** Cloud-specific event source lists for investigation panels. */

import type { Cloud } from "./catalog";

export const CONTROL_PLANE_SOURCES: Record<Cloud, string[]> = {
  aws: ["cloudtrail"],
  azure: ["activity_log", "entra_signin", "entra_audit"],
  gcp: ["cloud_audit_admin", "cloud_audit_data"],
};

export const FLOW_SOURCES: Record<Cloud, string[]> = {
  aws: ["vpc_flow"],
  azure: ["nsg_flow"],
  gcp: ["vpc_flow"],
};

export const FINDING_SOURCES: Record<Cloud, string[]> = {
  aws: ["guardduty", "securityhub", "inspector2", "macie", "detective"],
  azure: ["defender"],
  gcp: ["scc_findings"],
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

export function caseCloud(manifestCloud?: string | null): Cloud {
  if (manifestCloud === "azure" || manifestCloud === "gcp") return manifestCloud;
  return "aws";
}
