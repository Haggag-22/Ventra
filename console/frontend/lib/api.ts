// API client. All requests go to /api/* which Next rewrites to the local backend — the
// browser never makes a cross-origin or external call.

import type {
  CaseSummary,
  CloudTrailCollection,
  EventsResponse,
  Facets,
  IdentityResponse,
  IntegrityReport,
  InventorySummary,
  NetworkResponse,
  TimelineResponse,
} from "./types";

export type EventParams = {
  q?: string;
  source?: string[];
  severity?: string[];
  category?: string[];
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
  timeline: (c: string, p: EventParams = {}) =>
    get<TimelineResponse>(`/cases/${c}/timeline${qs(p)}`),
  identity: (c: string) => get<IdentityResponse>(`/cases/${c}/identity`),
  network: (c: string) => get<NetworkResponse>(`/cases/${c}/network`),
  resources: (c: string) => get<InventorySummary>(`/cases/${c}/resources`),
  inventorySummary: (c: string) => get<InventorySummary>(`/cases/${c}/inventory/summary`),
  inventory: (c: string, source: string) =>
    get<{ source: string; data: any }>(`/cases/${c}/inventory/${source}`),
  cloudtrailCollection: (c: string) =>
    get<CloudTrailCollection>(`/cases/${c}/cloudtrail/collection`),
};

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
