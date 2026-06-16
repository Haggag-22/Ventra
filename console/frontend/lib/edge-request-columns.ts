/** Edge request log table — ELB/ALB and CloudFront access log events. */

import type { UnifiedEvent } from "./types";

export type EdgeRequestColKey =
  | "timestamp"
  | "source"
  | "method"
  | "request"
  | "client_ip"
  | "status"
  | "resource"
  | "region";

export interface EdgeRequestColumn {
  key: EdgeRequestColKey;
  label: string;
  min: number;
  locked?: boolean;
}

export const EDGE_REQUEST_COLS: EdgeRequestColumn[] = [
  { key: "timestamp", label: "Time (UTC)", min: 120, locked: true },
  { key: "source", label: "Source", min: 110 },
  { key: "method", label: "Method", min: 70 },
  { key: "request", label: "Request", min: 220 },
  { key: "client_ip", label: "Client IP", min: 120 },
  { key: "status", label: "Status", min: 70 },
  { key: "resource", label: "Resource", min: 140 },
  { key: "region", label: "Region", min: 90 },
];

export const DEFAULT_EDGE_REQUEST_WIDTHS: Record<EdgeRequestColKey, number> = {
  timestamp: 190,
  source: 120,
  method: 80,
  request: 360,
  client_ip: 130,
  status: 80,
  resource: 160,
  region: 100,
};

export const EDGE_REQUEST_WIDTHS_KEY = "ventra.edge-request-table.widths";
export const EDGE_REQUEST_VISIBLE_COLS_KEY = "ventra.edge-request-table.visible-cols";

export const ALL_EDGE_REQUEST_COL_KEYS: EdgeRequestColKey[] = EDGE_REQUEST_COLS.map((c) => c.key);

export const EDGE_SOURCE_LABEL: Record<string, string> = {
  elb_alb: "ELB / ALB",
  cloudfront: "CloudFront",
};

export const EDGE_SOURCE_CHIP: Record<string, string> = {
  elb_alb: "border-accent/35 bg-accent/10 text-accent",
  cloudfront: "border-ok-green/35 bg-ok-green/10 text-ok-green",
};

export function loadEdgeRequestWidths(): Record<EdgeRequestColKey, number> {
  if (typeof window === "undefined") return DEFAULT_EDGE_REQUEST_WIDTHS;
  try {
    const raw = localStorage.getItem(EDGE_REQUEST_WIDTHS_KEY);
    if (!raw) return DEFAULT_EDGE_REQUEST_WIDTHS;
    return { ...DEFAULT_EDGE_REQUEST_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_EDGE_REQUEST_WIDTHS;
  }
}

export function loadVisibleEdgeRequestCols(): EdgeRequestColKey[] {
  if (typeof window === "undefined") return [...ALL_EDGE_REQUEST_COL_KEYS];
  try {
    const raw = localStorage.getItem(EDGE_REQUEST_VISIBLE_COLS_KEY);
    if (!raw) return [...ALL_EDGE_REQUEST_COL_KEYS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is EdgeRequestColKey =>
      ALL_EDGE_REQUEST_COL_KEYS.includes(k as EdgeRequestColKey),
    );
    return valid.length > 0 ? valid : [...ALL_EDGE_REQUEST_COL_KEYS];
  } catch {
    return [...ALL_EDGE_REQUEST_COL_KEYS];
  }
}

export function orderedVisibleEdgeRequestCols(visible: EdgeRequestColKey[]): EdgeRequestColumn[] {
  const set = new Set(visible);
  return EDGE_REQUEST_COLS.filter((c) => set.has(c.key));
}

/** HTTP status code from the normalized message (`→ 404`) or raw log line. */
export function edgeHttpStatus(event: UnifiedEvent): string {
  const fromMsg = event.message.match(/→ (\d{3})/);
  if (fromMsg) return fromMsg[1];
  const line = String(event.raw?.line ?? "");
  const alb = line.match(/\s(\d{3})\s+\d{3}\s+\d+\s+\d+/);
  if (alb) return alb[1];
  const cf = line.split("\t");
  if (cf.length > 8 && /^\d{3}$/.test(cf[7])) return cf[7];
  return "";
}

export function edgeStatusTone(status: string): string {
  const code = Number.parseInt(status, 10);
  if (Number.isNaN(code)) return "text-fg-subtle";
  if (code >= 500) return "text-bad-red";
  if (code >= 400) return "text-warn-amber";
  if (code >= 300) return "text-accent";
  return "text-ok-green";
}
