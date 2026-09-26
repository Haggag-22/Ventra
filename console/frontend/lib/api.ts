// API client. All requests go to /api/* which Next rewrites to the local backend — the
// browser never makes a cross-origin or external call.

import type {
  Artifact,
  ArtifactPack,
  CaseOverview,
  CaseSummary,
  CloudTrailCollection,
  CloudWatchCollection,
  VpcFlowCollection,
  CollectorMatrixRow,
  EventsResponse,
  ExportableCase,
  ExportTarget,
  Facets,
  IdentityResponse,
  DataAccessResponse,
  IntegrityReport,
  InventorySummary,
  EvidenceContent,
  EvidenceIndex,
  EvidenceLines,
  NetworkResponse,
  NetworkVpcsResponse,
  RunMatrix,
  RunMeta,
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
  vpcs?: string[];
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

/** Shown when the Next.js /api proxy cannot reach the FastAPI backend. */
export const BACKEND_UNREACHABLE =
  "Can't reach backend — run `ventra dev` from the Ventra repo root (starts console on :8080 and API on :8000).";

const API_TIMEOUT_MS = 15_000;

/** Options for apiFetch. `timeoutMs: null` disables the default timeout (long downloads). */
type ApiFetchInit = RequestInit & { timeoutMs?: number | null };

function isProxyOrNetworkFailure(err: unknown): boolean {
  if (err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError")) {
    return true;
  }
  return err instanceof TypeError;
}

async function apiFetch(input: RequestInfo | URL, init?: ApiFetchInit): Promise<Response> {
  const { timeoutMs = API_TIMEOUT_MS, signal: userSignal, ...fetchInit } = init ?? {};
  try {
    const opts: RequestInit = { ...fetchInit };
    const signals: AbortSignal[] = [];
    if (userSignal) signals.push(userSignal);
    if (timeoutMs != null && timeoutMs > 0) {
      signals.push(AbortSignal.timeout(timeoutMs));
    }
    if (signals.length === 1) opts.signal = signals[0];
    else if (signals.length > 1) opts.signal = AbortSignal.any(signals);
    return await fetch(input, opts);
  } catch (err) {
    // User-initiated cancel must not be rewritten as "backend unreachable".
    if (userSignal?.aborted) throw err;
    if (isProxyOrNetworkFailure(err)) throw new Error(BACKEND_UNREACHABLE);
    throw err;
  }
}

function throwIfBackendDown(res: Response): void {
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    throw new Error(BACKEND_UNREACHABLE);
  }
}

function isNextProxyBackendDown(status: number, body: string): boolean {
  // Next.js rewrites to a stopped FastAPI process as 500 + plain "Internal Server Error".
  return status === 500 && body.trim() === "Internal Server Error";
}

async function get<T>(path: string): Promise<T> {
  const res = await apiFetch(`/api${path}`, { headers: { Accept: "application/json" } });
  throwIfBackendDown(res);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    if (isNextProxyBackendDown(res.status, body)) throw new Error(BACKEND_UNREACHABLE);
    throw new Error(`${res.status} ${res.statusText}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<{ status: string; version: string; telemetry: boolean }>("/health"),
  me: () => get<{ role: string; capabilities: string[] }>("/me"),
  cases: () => get<{ cases: CaseSummary[] }>("/cases"),
  summary: (c: string) => get<CaseSummary>(`/cases/${c}/summary`),
  integrity: (c: string) => get<IntegrityReport>(`/cases/${c}/integrity`),
  manifest: (c: string) => get<Record<string, any>>(`/cases/${c}/manifest`),
  collectionLog: (c: string) => get<{ entries: any[] }>(`/cases/${c}/collection-log`),
  events: (c: string, p: EventParams = {}) =>
    get<EventsResponse>(`/cases/${c}/events${qs(p)}`),
  facets: (c: string, p: EventParams = {}) => get<Facets>(`/cases/${c}/events/facets${qs(p)}`),
  identity: (c: string) => get<IdentityResponse>(`/cases/${c}/identity`),
  network: (c: string, p: { vpc?: string } = {}) =>
    get<NetworkResponse>(`/cases/${c}/network${qs(p)}`),
  networkVpcs: (c: string) => get<NetworkVpcsResponse>(`/cases/${c}/network/vpcs`),
  webDns: (c: string) => get<WebDnsResponse>(`/cases/${c}/web-dns`),
  dataAccess: (c: string) => get<DataAccessResponse>(`/cases/${c}/data-access`),
  resources: (c: string) => get<InventorySummary>(`/cases/${c}/resources`),
  inventorySummary: (c: string) => get<InventorySummary>(`/cases/${c}/inventory/summary`),
  inventory: (c: string, source: string) =>
    get<{ source: string; data: any }>(`/cases/${c}/inventory/${source}`),
  cloudtrailCollection: (c: string) =>
    get<CloudTrailCollection>(`/cases/${c}/cloudtrail/collection`),
  cloudwatchCollection: (c: string) =>
    get<CloudWatchCollection>(`/cases/${c}/cloudwatch/collection`),
  vpcFlowCollection: (c: string) =>
    get<VpcFlowCollection>(`/cases/${c}/vpc-flow/collection`),
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
  enterpriseSettings: () =>
    get<{ ingest_s3_prefix: string; max_upload_mb: number }>("/enterprise/settings"),
  overview: (c: string) => get<CaseOverview>(`/cases/${c}/overview`),
};

// ---- Configuration (connections + profiles) --------------------------------------------

export type Connection = {
  id: string;
  name: string;
  platform: string;
  /** Secret fields saved on the server; the API never returns their values. */
  stored_secrets?: string[];
  alias?: string;
  auth_method?: string;
  aws_access_key_id?: string;
  aws_secret_access_key?: string;
  aws_session_token?: string;
  profile_name?: string;
  role_arn?: string;
  aws_account_id?: string;
  project?: string;
  subscription?: string;
  m365_domain?: string;
  azure_tenant_id?: string;
  azure_client_id?: string;
  azure_client_secret?: string;
  azure_client_certificate_content?: string;
  gcp_service_account_json?: string;
  k8s_context?: string;
  kubeconfig_content?: string;
  created_at?: string;
  last_tested_at?: string;
  last_test_ok?: boolean;
};

export type CollectionProfile = AcquisitionBuild & {
  id: string;
  name: string;
};

const CONFIG_HEADERS = { "X-Ventra-Role": "investigator" };

async function configRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(`/api${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...CONFIG_HEADERS,
      ...init?.headers,
    },
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export function listConnections(): Promise<{ connections: Connection[] }> {
  return configRequest("/config/connections");
}

export function createConnection(
  body: Omit<Connection, "id">,
): Promise<Connection> {
  return configRequest("/config/connections", { method: "POST", body: JSON.stringify(body) });
}

export function updateConnection(
  id: string,
  body: Partial<Omit<Connection, "id">>,
): Promise<Connection> {
  return configRequest(`/config/connections/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function deleteConnection(id: string): Promise<{ deleted: string }> {
  return configRequest(`/config/connections/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function testConnection(id: string): Promise<{
  ok: boolean;
  platform?: string;
  account_id?: string;
  arn?: string;
  tenant_id?: string;
  principal?: string;
  project_id?: string;
  context?: string;
  cluster?: string;
  error?: string;
}> {
  return configRequest(`/config/connections/${encodeURIComponent(id)}/test`, { method: "POST" });
}

export function listProfiles(): Promise<{ profiles: CollectionProfile[] }> {
  return configRequest("/config/profiles");
}

export function createProfile(body: AcquisitionBuild & { name: string }): Promise<CollectionProfile> {
  return configRequest("/config/profiles", { method: "POST", body: JSON.stringify(body) });
}

export function updateProfile(
  id: string,
  body: Partial<AcquisitionBuild & { name: string }>,
): Promise<CollectionProfile> {
  return configRequest(`/config/profiles/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function deleteProfile(id: string): Promise<{ deleted: string }> {
  return configRequest(`/config/profiles/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function getProfile(id: string): Promise<CollectionProfile> {
  const { profiles } = await listProfiles();
  const profile = profiles.find((p) => p.id === id);
  if (!profile) throw new Error(`Profile not found: ${id}`);
  return profile;
}

// ---- Collection runs -------------------------------------------------------------------

export function runEventsUrl(runId: string): string {
  return `/api/runs/${encodeURIComponent(runId)}/events`;
}

export function getRunEventLog(runId: string): Promise<{ events: Record<string, unknown>[] }> {
  return get<{ events: Record<string, unknown>[] }>(
    `/runs/${encodeURIComponent(runId)}/event-log`,
  );
}

export async function startRun(body: AcquisitionBuild & { auto_ingest?: boolean; connection_id?: string }): Promise<{ run_id: string }> {
  const res = await apiFetch("/api/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Ventra-Role": "responder" },
    body: JSON.stringify({ ...body, auto_ingest: body.auto_ingest ?? true }),
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to start run");
  }
  return res.json() as Promise<{ run_id: string }>;
}

export function listRuns(): Promise<{ runs: RunMeta[] }> {
  return get<{ runs: RunMeta[] }>("/runs");
}

export function getRun(runId: string): Promise<RunMeta> {
  return get<RunMeta>(`/runs/${encodeURIComponent(runId)}`);
}

export async function cancelRun(runId: string): Promise<RunMeta> {
  const res = await apiFetch(`/api/runs/${encodeURIComponent(runId)}/cancel`, {
    method: "POST",
    headers: { "X-Ventra-Role": "responder" },
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to cancel run");
  }
  return res.json() as Promise<RunMeta>;
}

export function parseRunMatrix(runId: string, raw: Record<string, unknown>): RunMatrix {
  return {
    run_id: runId,
    status: raw.status as RunMatrix["status"],
    complete: Number(raw.complete ?? 0),
    total: Number(raw.total ?? 0),
    masked_account: raw.masked_account as string | undefined,
    case_id: raw.case_id as string | undefined,
    regions: raw.regions as string[] | undefined,
    rows: ((raw.collectors ?? raw.rows ?? []) as CollectorMatrixRow[]).map((c) => ({
      name: c.name,
      status: c.status,
      severity: c.severity,
      records: c.records,
      elapsed_ms: c.elapsed_ms,
      detail: c.detail,
      live_msg: c.live_msg,
    })),
  };
}

export function getRunMatrix(runId: string): Promise<RunMatrix> {
  return get<Record<string, unknown>>(`/runs/${encodeURIComponent(runId)}/matrix`).then((raw) =>
    parseRunMatrix(runId, raw),
  );
}

export async function deleteCase(caseId: string): Promise<{ deleted: string }> {
  // Deleting a case is a Data Custodian action. In a real deployment the role is set by the
  // upstream auth proxy; locally the single analyst holds every role, so we assert it here.
  const res = await apiFetch(`/api/cases/${encodeURIComponent(caseId)}`, {
    method: "DELETE",
    headers: { "X-Ventra-Role": "data_custodian" },
  });
  throwIfBackendDown(res);
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
  const res = await apiFetch("/api/cases/import", { method: "POST", body: form });
  throwIfBackendDown(res);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "Import failed");
  }
  return res.json();
}

export type S3ImportResult = {
  ingested: {
    case_id: string;
    events: number;
    integrity: string;
    s3_key: string;
    warnings: string[];
  }[];
  skipped: number;
  errors: { s3_key: string; error: string }[];
};

export async function importFromS3(s3Prefix?: string): Promise<S3ImportResult> {
  const res = await apiFetch("/api/cases/import/s3", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ s3_prefix: s3Prefix?.trim() || "" }),
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "S3 import failed");
  }
  return res.json();
}

export async function exportCaseElastic(caseId: string): Promise<void> {
  // Large cases can take minutes to serialize; do not use the default 15s API timeout.
  const res = await apiFetch(`/api/cases/${encodeURIComponent(caseId)}/export/elastic`, {
    method: "POST",
    headers: { "X-Ventra-Role": "investigator" },
    timeoutMs: null,
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "Export failed");
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${caseId}-elastic-export.zip`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function listExportableCases(): Promise<{ cases: ExportableCase[] }> {
  const res = await apiFetch("/api/cases/exportable", {
    headers: { "X-Ventra-Role": "investigator" },
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || "Failed to load cases");
  }
  return res.json();
}

export type ExportCasesBatchBody = {
  case_ids: string[];
  target: ExportTarget;
  sources?: string[];
  since?: string;
  until?: string;
  /** Abort cancels the server job and stops polling/download. */
  signal?: AbortSignal;
};

type ExportJobStatus = {
  job_id: string;
  status: "pending" | "running" | "ready" | "error" | "cancelled";
  error?: string | null;
  filename?: string | null;
};

export class ExportCancelledError extends Error {
  constructor(message = "Export cancelled") {
    super(message);
    this.name = "ExportCancelledError";
  }
}

async function cancelExportJob(jobId: string): Promise<void> {
  try {
    await apiFetch(`/api/cases/export/${encodeURIComponent(jobId)}/cancel`, {
      method: "POST",
      headers: { "X-Ventra-Role": "investigator" },
    });
  } catch {
    // Best-effort — UI unlocks either way.
  }
}

/**
 * Export one or more cases and download the resulting zip.
 *
 * The zip is built server-side as a job: large cases take minutes to serialize, and a single
 * blocking request made the dev proxy/client reset the connection ("socket hang up") before
 * the zip was ready. Here we start the job, poll until it is ready, then download the finished
 * file (which streams immediately). Pass ``signal`` to cancel mid-flight.
 */
export async function exportCasesBatch(body: ExportCasesBatchBody): Promise<void> {
  const { signal, ...payload } = body;
  if (signal?.aborted) throw new ExportCancelledError();

  const startRes = await apiFetch("/api/cases/export", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Ventra-Role": "investigator" },
    body: JSON.stringify(payload),
    signal,
  });
  throwIfBackendDown(startRes);
  if (!startRes.ok) {
    const err = await startRes.json().catch(() => ({ detail: startRes.statusText }));
    throw new Error(err.detail || "Export failed");
  }
  const { job_id: jobId } = (await startRes.json()) as { job_id: string };

  const onAbort = () => {
    void cancelExportJob(jobId);
  };
  signal?.addEventListener("abort", onAbort);

  try {
    for (;;) {
      if (signal?.aborted) {
        await cancelExportJob(jobId);
        throw new ExportCancelledError();
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
      if (signal?.aborted) {
        await cancelExportJob(jobId);
        throw new ExportCancelledError();
      }
      const statusRes = await apiFetch(`/api/cases/export/${encodeURIComponent(jobId)}`, {
        headers: { "X-Ventra-Role": "investigator" },
        signal,
      });
      throwIfBackendDown(statusRes);
      if (!statusRes.ok) {
        const err = await statusRes.json().catch(() => ({ detail: statusRes.statusText }));
        throw new Error(err.detail || "Export failed");
      }
      const job = (await statusRes.json()) as ExportJobStatus;
      if (job.status === "cancelled") throw new ExportCancelledError();
      if (job.status === "error") throw new Error(job.error || "Export failed");
      if (job.status === "ready") break;
    }

    const res = await apiFetch(`/api/cases/export/${encodeURIComponent(jobId)}/download`, {
      headers: { "X-Ventra-Role": "investigator" },
      timeoutMs: null,
      signal,
    });
    throwIfBackendDown(res);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Export failed");
    }
    const blob = await res.blob();
    if (signal?.aborted) throw new ExportCancelledError();
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match?.[1] || `ventra-export-${body.target}.zip`;

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    if (signal?.aborted || (e instanceof DOMException && e.name === "AbortError")) {
      await cancelExportJob(jobId);
      throw new ExportCancelledError();
    }
    throw e;
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}

import type { GcpLogBackendConfig } from "./gcp-log-backend";

export type AcquisitionBuild = {
  cloud: string;
  case_id?: string;
  artifacts?: string[];
  pack?: string;
  include_iam?: boolean;
  since?: string;
  until?: string;
  regions?: string[];
  project?: string;
  subscription?: string;
  azure_tenant_id?: string;
  azure_client_id?: string;
  aws_profile?: string;
  max_records_per_source?: number | null;
  artifact_parameters?: Record<string, Record<string, unknown>>;
  deployment_profile?: string;
  transport?: string;
  gcp_log_backend?: GcpLogBackendConfig;
  bundle_wheel?: boolean;
  require_wheel?: boolean;
  connection_id?: string;
  /** Saved Acquire kit display name — zip and entry script use this. */
  kit_name?: string;
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
  wheel_source: "local" | "pypi" | "cli";
};

/** Preview IAM narrowing and kit metadata before download. */
export async function previewAcquisitionKit(body: AcquisitionBuild): Promise<AcquisitionPreview> {
  const res = await apiFetch("/api/acquisitions/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Ventra-Role": "responder" },
    body: JSON.stringify(body),
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Kit preview failed");
  }
  return res.json() as Promise<AcquisitionPreview>;
}

/** POST the acquisition selection and trigger a browser download of the returned kit zip. */
export async function buildAcquisitionKit(body: AcquisitionBuild): Promise<void> {
  const res = await apiFetch("/api/acquisitions/build", {
    method: "POST",
    // The Responder role owns the acquisition phase (matches backend RBAC).
    headers: { "Content-Type": "application/json", "X-Ventra-Role": "responder" },
    body: JSON.stringify(body),
    // Kit builds mint credentials + package bytes; do not abort mid-download.
    timeoutMs: null,
  });
  throwIfBackendDown(res);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Kit build failed");
  }
  const buf = await res.arrayBuffer();
  if (buf.byteLength < 4) {
    throw new Error("Kit download was empty — try again.");
  }
  const magic = new Uint8Array(buf.slice(0, 2));
  // ZIP local file header is "PK"
  if (magic[0] !== 0x50 || magic[1] !== 0x4b) {
    const preview = new TextDecoder().decode(buf.slice(0, 120)).replace(/\s+/g, " ").slice(0, 100);
    throw new Error(
      `Kit download was not a valid archive (got ${buf.byteLength} bytes). Preview: ${preview}`,
    );
  }
  const blob = new Blob([buf], { type: "application/zip" });
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename =
    match?.[1] ||
    (() => {
      const raw = (body.kit_name || "").trim() || `ventra-kit-${body.cloud}-${body.case_id}`;
      const slug = raw
        .replace(/[^\w.\-]+/g, "-")
        .replace(/-{2,}/g, "-")
        .replace(/^[.\-]+|[.\-]+$/g, "")
        .slice(0, 80);
      return `${slug || "ventra-kit"}.kit`;
    })();

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
