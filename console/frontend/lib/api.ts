// API client. All requests go to /api/* which Next rewrites to the local backend — the
// browser never makes a cross-origin or external call.

import type {
  Artifact,
  ArtifactPack,
  CaseSummary,
  CloudTrailCollection,
  EventsResponse,
  Facets,
  IdentityResponse,
  DataAccessResponse,
  IntegrityReport,
  InventorySummary,
  EvidenceContent,
  EvidenceIndex,
  EvidenceLines,
  NetworkResponse,
  WebDnsResponse,
} from "./types";

export type EventParams = {
  q?: string;
  source?: string[];
  severity?: string[];
  category?: string[];
  trail_category?: string[];
  finding_class?: string[];
  actions?: string[];
  regions?: string[];
  services?: string[];
  users?: string[];
  action?: string;
  user?: string;
  user_type?: string;
  ip?: string;
  outcome?: string;
  region?: string;
  service?: string;
  kind?: string;
  ua_category?: string;
  related_ip?: string;
  related_user?: string;
  related_resource?: string;
  resources?: string[];
  http_status?: string[];
  outcomes?: string[];
  source_ips?: string[];
  dest_ips?: string[];
  dest_ports?: string[];
  data_access?: boolean;
  since?: string;
  until?: string;
  sort?: string;
  order?: string;
  limit?: number;
  offset?: number;
};

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, String(x)));
    else sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<{ status: string; version: string; telemetry: boolean }>("/health"),
  me: () => get<{ role: string }>("/me"),
  cases: () => get<{ cases: CaseSummary[] }>("/cases"),
  summary: (c: string) => get<CaseSummary>(`/cases/${c}/summary`),
  integrity: (c: string) => get<IntegrityReport>(`/cases/${c}/integrity`),
  manifest: (c: string) => get<Record<string, any>>(`/cases/${c}/manifest`),
  collectionLog: (c: string) => get<{ entries: any[] }>(`/cases/${c}/collection-log`),
  events: (c: string, p: EventParams = {}) =>
    get<EventsResponse>(`/cases/${c}/events${qs(p)}`),
  facets: (c: string, p: EventParams = {}) => get<Facets>(`/cases/${c}/events/facets${qs(p)}`),
  identity: (c: string) => get<IdentityResponse>(`/cases/${c}/identity`),
  network: (c: string) => get<NetworkResponse>(`/cases/${c}/network`),
  webDns: (c: string) => get<WebDnsResponse>(`/cases/${c}/web-dns`),
  dataAccess: (c: string) => get<DataAccessResponse>(`/cases/${c}/data-access`),
  resources: (c: string) => get<InventorySummary>(`/cases/${c}/resources`),
  inventorySummary: (c: string) => get<InventorySummary>(`/cases/${c}/inventory/summary`),
  inventory: (c: string, source: string) =>
    get<{ source: string; data: any }>(`/cases/${c}/inventory/${source}`),
  cloudtrailCollection: (c: string) =>
    get<CloudTrailCollection>(`/cases/${c}/cloudtrail/collection`),
  evidenceIndex: (c: string) => get<EvidenceIndex>(`/cases/${c}/evidence`),
  evidenceContent: (c: string, path: string, maxBytes?: number) =>
    get<EvidenceContent>(
      `/cases/${c}/evidence/content${qs({ path, max_bytes: maxBytes })}`,
    ),
  evidenceLines: (c: string, path: string, offset = 0, limit?: number) =>
    get<EvidenceLines>(
      `/cases/${c}/evidence/lines${qs({ path, offset, limit })}`,
    ),
  evidenceDownloadUrl: (c: string, path: string) =>
    `/api/cases/${encodeURIComponent(c)}/evidence/download?path=${encodeURIComponent(path)}`,
  artifacts: (cloud?: string, search?: string) =>
    get<{ artifacts: Artifact[]; count: number }>(`/artifacts${qs({ cloud, search })}`),
  artifact: (collector: string, cloud?: string) =>
    get<Artifact>(`/artifacts/${encodeURIComponent(collector)}${qs({ cloud })}`),
  packs: (cloud?: string) => get<{ packs: ArtifactPack[] }>(`/packs${qs({ cloud })}`),
};

export async function deleteCase(caseId: string): Promise<{ deleted: string }> {
  // Deleting a case is a Data Custodian action. In a real deployment the role is set by the
  // upstream auth proxy; locally the single analyst holds every role, so we assert it here.
  const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}`, {
    method: "DELETE",
    headers: { "X-Ventra-Role": "data_custodian" },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "Delete failed");
  }
  return res.json();
}

export async function importPackage(file: File, caseId?: string): Promise<any> {
  const form = new FormData();
  form.append("file", file);
  if (caseId?.trim()) form.append("case_id", caseId.trim());
  const res = await fetch("/api/cases/import", { method: "POST", body: form });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "Import failed");
  }
  return res.json();
}

export type AcquisitionBuild = {
  cloud: string;
  case_id: string;
  artifacts?: string[];
  pack?: string;
  include_iam?: boolean;
  since?: string;
  until?: string;
  regions?: string[];
  project?: string;
  subscription?: string;
  max_records_per_source?: number | null;
  artifact_parameters?: Record<string, Record<string, unknown>>;
  deployment_profile?: string;
  bundle_wheel?: boolean;
  require_wheel?: boolean;
};

export type AcquisitionPreview = {
  ventra_version: string;
  cloud: string;
  artifact_count: number;
  collectors: string[];
  implicit_collectors: string[];
  iam_included: boolean;
  iam_policy_files: string[];
  iam_action_count: number;
  iam_actions: string[];
  iam_policies: Record<string, Record<string, unknown>>;
  deployment_profile: string;
  bundle_wheel: boolean;
  wheel_source: "local" | "pypi";
};

/** Preview IAM narrowing and kit metadata before download. */
export async function previewAcquisitionKit(body: AcquisitionBuild): Promise<AcquisitionPreview> {
  const res = await fetch("/api/acquisitions/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Ventra-Role": "responder" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Kit preview failed");
  }
  return res.json() as Promise<AcquisitionPreview>;
}

/** POST the acquisition selection and trigger a browser download of the returned kit zip. */
export async function buildAcquisitionKit(body: AcquisitionBuild): Promise<void> {
  const res = await fetch("/api/acquisitions/build", {
    method: "POST",
    // The Responder role owns the acquisition phase (matches backend RBAC).
    headers: { "Content-Type": "application/json", "X-Ventra-Role": "responder" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Kit build failed");
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match?.[1] || `ventra-kit-${body.cloud}-${body.case_id}.zip`;

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
