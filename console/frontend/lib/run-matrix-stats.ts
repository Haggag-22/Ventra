import type { CollectorMatrixRow } from "@/lib/types";

export type RowPhase = "pass" | "fail" | "running" | "pending" | "partial" | "other";

export interface RunMatrixStats {
  pass: number;
  fail: number;
  running: number;
  pending: number;
  partial: number;
  totalRecords: number;
  complete: number;
  total: number;
  pct: number;
  activeCollector: string | null;
  severityCounts: Record<string, number>;
  collected: { name: string; records: number; severity?: string }[];
  gaps: { name: string; status: string; detail?: string; severity?: string }[];
}

export function rowPhase(status: string): RowPhase {
  const s = status.toLowerCase();
  if (["pass", "ok", "success", "collected"].includes(s)) return "pass";
  if (["fail", "failed", "error", "skipped"].includes(s)) return "fail";
  if (s === "running") return "running";
  if (s === "pending") return "pending";
  if (s === "partial") return "partial";
  return "other";
}

export function isTerminalRow(status: string): boolean {
  const p = rowPhase(status);
  return p === "pass" || p === "fail" || p === "partial";
}

export function effectiveRowStatus(status: string, runCancelled: boolean): string {
  if (!runCancelled) return status;
  const phase = rowPhase(status);
  if (phase === "running" || phase === "pending") return "fail";
  return status;
}

export function computeRunMatrixStats(
  rows: CollectorMatrixRow[],
  complete?: number,
  total?: number,
  runCancelled = false,
): RunMatrixStats {
  let pass = 0;
  let fail = 0;
  let running = 0;
  let pending = 0;
  let partial = 0;
  let totalRecords = 0;
  let activeCollector: string | null = null;
  const severityCounts: Record<string, number> = {};

  const collected: RunMatrixStats["collected"] = [];
  const gaps: RunMatrixStats["gaps"] = [];

  for (const row of rows) {
    const phase = rowPhase(effectiveRowStatus(row.status, runCancelled));
    if (phase === "pass") pass += 1;
    else if (phase === "fail") fail += 1;
    else if (phase === "running") {
      running += 1;
      if (!activeCollector) activeCollector = row.name;
    } else if (phase === "pending") pending += 1;
    else if (phase === "partial") partial += 1;

    if (row.records != null && row.records > 0) totalRecords += row.records;

    if (phase === "pass" || phase === "partial") {
      collected.push({
        name: row.name,
        records: row.records ?? 0,
        severity: row.severity,
      });
      const sev = (row.severity ?? "info").toLowerCase();
      severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
    } else if (phase === "fail") {
      gaps.push({
        name: row.name,
        status: row.status,
        detail: row.detail,
        severity: row.severity,
      });
    }
  }

  const resolvedTotal = total ?? rows.length;
  const resolvedComplete =
    complete ??
    rows.filter((r) => isTerminalRow(effectiveRowStatus(r.status, runCancelled))).length;

  return {
    pass,
    fail,
    running,
    pending,
    partial,
    totalRecords,
    complete: resolvedComplete,
    total: resolvedTotal,
    pct: resolvedTotal > 0 ? resolvedComplete / resolvedTotal : 0,
    activeCollector,
    severityCounts,
    collected: collected.sort((a, b) => b.records - a.records),
    gaps,
  };
}

export function computeGapRows(
  rows: CollectorMatrixRow[],
  cancelled: boolean,
): { name: string; status: string; detail?: string }[] {
  return rows
    .filter((row) => {
      const phase = rowPhase(effectiveRowStatus(row.status, cancelled));
      if (phase === "fail") return true;
      if (cancelled && (phase === "pending" || phase === "running")) return true;
      return false;
    })
    .map((row) => ({
      name: row.name,
      status: effectiveRowStatus(row.status, cancelled),
      detail: row.detail ?? (cancelled ? "Cancelled" : undefined),
    }));
}

export function fmtElapsedLive(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}
