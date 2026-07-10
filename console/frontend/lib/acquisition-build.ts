import type { ParamValues } from "@/components/acquire-param-fields";
import { serializeParamValues } from "@/components/acquire-param-fields";
import type { AcquisitionBuild, CollectionProfile } from "@/lib/api";
import { normalizeCaseId } from "@/lib/case-id";
import type { AcquirePlatform } from "@/lib/catalog";
import type { DeploymentProfile } from "@/lib/deployment-profiles";
import {
  DEFAULT_GCP_LOG_BACKEND_FORM,
  gcpConfigToForm,
  serializeGcpLogBackend,
  type GcpLogBackendFormState,
} from "@/lib/gcp-log-backend";
import type { Artifact } from "@/lib/types";

export function joinScopeValues(values: string[]): string | undefined {
  const cleaned = values.map((v) => v.trim()).filter(Boolean);
  return cleaned.length ? cleaned.join(",") : undefined;
}

export function splitScope(raw?: string): string[] {
  if (!raw?.trim()) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

export type KitRunScopeState = {
  since: string;
  until: string;
  regions: string;
  projectIds: string[];
  subscriptionIds: string[];
  azureTenantId: string;
  azureClientId: string;
  awsProfile: string;
  maxRecordsPerSource: string;
  gcpLogBackend: GcpLogBackendFormState;
};

export function scopeStateFromProfile(profile: CollectionProfile): KitRunScopeState {
  return {
    since: profile.since || "",
    until: profile.until || "",
    regions: (profile.regions || []).join(","),
    projectIds: splitScope(profile.project),
    subscriptionIds: splitScope(profile.subscription),
    azureTenantId: profile.azure_tenant_id || "",
    azureClientId: profile.azure_client_id || "",
    awsProfile: profile.aws_profile || "",
    maxRecordsPerSource:
      profile.max_records_per_source != null ? String(profile.max_records_per_source) : "",
    gcpLogBackend: profile.gcp_log_backend
      ? gcpConfigToForm(profile.gcp_log_backend)
      : { ...DEFAULT_GCP_LOG_BACKEND_FORM },
  };
}

export function profileToRunBody(profile: CollectionProfile): Omit<AcquisitionBuild, "case_id"> {
  const { id: _id, name: _name, case_id: _caseId, ...body } = profile;
  return body;
}

export function parseMaxRecords(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) return undefined;
  return n;
}

export function buildRequestBody(
  platform: AcquirePlatform,
  caseId: string,
  collectors: string[],
  since: string,
  until: string,
  regions: string,
  projectIds: string[],
  subscriptionIds: string[],
  azureTenantId: string,
  azureClientId: string,
  awsProfile: string,
  artifactParams: Record<string, ParamValues>,
  cartForCloud: Artifact[],
  deploymentProfile: DeploymentProfile,
  maxRecordsPerSource: string,
  transport?: string,
  gcpLogBackend?: GcpLogBackendFormState,
): AcquisitionBuild {
  const regionList = regions
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
  const params: Record<string, Record<string, unknown>> = {};
  for (const a of cartForCloud) {
    const p = artifactParams[a.collector];
    if (!p) continue;
    const serialized = serializeParamValues(p);
    if (Object.keys(serialized).length) {
      params[a.collector] = serialized;
    }
  }
  return {
    cloud: platform,
    case_id: normalizeCaseId(caseId),
    artifacts: collectors,
    include_iam: true,
    since: since.trim() || undefined,
    until: until.trim() || undefined,
    regions: regionList.length ? regionList : undefined,
    project: platform === "gcp" ? joinScopeValues(projectIds) : undefined,
    subscription: platform === "azure" ? joinScopeValues(subscriptionIds) : undefined,
    azure_tenant_id: platform === "azure" ? azureTenantId.trim() || undefined : undefined,
    azure_client_id: platform === "azure" ? azureClientId.trim() || undefined : undefined,
    aws_profile: platform === "aws" ? awsProfile.trim() || undefined : undefined,
    artifact_parameters: Object.keys(params).length ? params : undefined,
    deployment_profile: deploymentProfile,
    max_records_per_source: parseMaxRecords(maxRecordsPerSource),
    transport: transport?.trim() || undefined,
    gcp_log_backend:
      platform === "gcp" ? serializeGcpLogBackend(gcpLogBackend ?? DEFAULT_GCP_LOG_BACKEND_FORM) : undefined,
    bundle_wheel: true,
    require_wheel: true,
  };
}

export function buildKitDownloadRequest(
  profile: CollectionProfile,
  connectionId: string,
): AcquisitionBuild {
  return {
    ...profileToRunBody(profile),
    case_id: "CASE-PENDING",
    connection_id: connectionId.trim(),
    include_iam: true,
    bundle_wheel: true,
    require_wheel: true,
  };
}

export function buildKitRunRequest(
  profile: CollectionProfile,
  caseId: string,
  scope: KitRunScopeState,
): AcquisitionBuild {
  const platform = profile.cloud.toLowerCase();
  const usesAzureAuth = platform === "azure" || platform === "m365";
  const regionList = scope.regions
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
  return {
    ...profileToRunBody(profile),
    case_id: normalizeCaseId(caseId),
    since: scope.since.trim() || undefined,
    until: scope.until.trim() || undefined,
    regions: regionList.length ? regionList : undefined,
    project: platform === "gcp" ? joinScopeValues(scope.projectIds) : undefined,
    subscription: platform === "azure" ? joinScopeValues(scope.subscriptionIds) : undefined,
    azure_tenant_id: usesAzureAuth ? scope.azureTenantId.trim() || undefined : undefined,
    azure_client_id: usesAzureAuth ? scope.azureClientId.trim() || undefined : undefined,
    aws_profile: platform === "aws" ? scope.awsProfile.trim() || undefined : undefined,
    max_records_per_source: parseMaxRecords(scope.maxRecordsPerSource),
    gcp_log_backend:
      platform === "gcp" ? serializeGcpLogBackend(scope.gcpLogBackend) : undefined,
    include_iam: true,
    bundle_wheel: true,
    require_wheel: true,
  };
}
