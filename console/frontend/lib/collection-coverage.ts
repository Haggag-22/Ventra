// Logs coverage helpers — gap roll-up and manifest resolution.

import { CATALOG, type CatalogItem, type Cloud } from "./catalog";
import type { CloudTrailAspect, PanelCollectorRef } from "./panel-collectors";

/** Sub-artifact / category gaps rolled up to a catalog collector id. */
export const GAP_PARENT: Record<string, string> = {
  cloudtrail_s3: "cloudtrail",
  cloudtrail_config: "cloudtrail",
  insight_events: "cloudtrail",
  data_events: "cloudtrail",
  network_activity: "cloudtrail",
  management_events: "cloudtrail",
  log_validation: "cloudtrail",
};

/** Resolve a gap name (possibly suffixed, e.g. ``log_validation:trail``) to its catalog id. */
export function gapParent(name: string): string {
  const base = name.split(":")[0];
  return GAP_PARENT[base] ?? base;
}

export type CoverageState =
  | "collected"
  | "partial"
  | "empty"
  | "denied"
  | "not_enabled"
  | "not_run"
  | "planned";

export interface ManifestGap {
  name: string;
  reason: string;
  detail: string;
}

export interface ManifestSource {
  name: string;
  status: string;
  record_count?: number;
  notes?: string;
}

export interface ResolvedCoverage {
  state: CoverageState;
  records: number;
  detail: string;
  gaps: ManifestGap[];
}

const SOURCE_PRIORITY: Record<string, number> = {
  collected: 5,
  partial: 4,
  empty: 3,
  errored: 2,
  skipped: 1,
};

const GAP_TO_STATE: Record<string, CoverageState> = {
  access_denied: "denied",
  collector_error: "denied",
  service_not_enabled: "not_enabled",
  logging_not_configured: "not_enabled",
  not_present: "not_enabled",
  region_opted_out: "not_enabled",
  out_of_scope: "not_run",
};

export function catalogItems(cloud: Cloud): CatalogItem[] {
  return (CATALOG[cloud] ?? []).flatMap((g) => g.items);
}

/** Log sources with a Ventra collector today (maps to manifest `sources[].name`). */
export const IMPLEMENTED_LOG_COLLECTORS = new Set([
  "apigateway",
  "cloudtrail",
  "config",
  "vpc_flow",
  "guardduty",
  "securityhub",
  "detective",
  "inspector2",
  "lambda_logs",
  "macie",
  "waf",
  "elb_alb",
  "cloudfront",
  "s3_access",
  "route53_resolver",
  "rds",
  "eks_audit",
  "aks_audit",
  "activity_log",
  "entra_signin",
  "entra_audit",
  "nsg_flow",
  "defender",
  "cloud_audit_admin",
  "cloud_audit_system",
  "cloud_audit_data",
  "login_events",
  "firewall_logs",
  "load_balancer",
  "cloud_cdn",
  "api_gateway",
  "vm_logs",
  "cloud_functions",
  "storage_access",
  "bigquery_audit",
  "cloud_sql",
  "secret_manager",
  "scc_findings",
  "cloud_monitoring",
]);

const AWS_LOGS_BASELINE = new Set([
  "cloudtrail",
  "config",
  "vpc_flow",
  "guardduty",
  "waf",
]);

const AZURE_LOGS_BASELINE = new Set([
  "activity_log",
  "entra_signin",
  "entra_audit",
  "nsg_flow",
  "defender",
]);

const GCP_LOGS_BASELINE = new Set([
  "cloud_audit_admin",
  "cloud_audit_data",
  "vpc_flow",
  "scc_findings",
  "login_events",
]);

export function baselineCollectorIds(cloud: Cloud): string[] {
  const items = catalogItems(cloud);
  if (cloud === "aws") {
    return items.filter((i) => AWS_LOGS_BASELINE.has(i.id)).map((i) => i.id);
  }
  if (cloud === "azure") {
    return items.filter((i) => AZURE_LOGS_BASELINE.has(i.id)).map((i) => i.id);
  }
  if (cloud === "gcp") {
    return items.filter((i) => GCP_LOGS_BASELINE.has(i.id)).map((i) => i.id);
  }
  return items.map((i) => i.id);
}

export function aggregateManifestSources(sources: ManifestSource[] = []) {
  const bySource = new Map<string, { status: string; records: number; notes: string }>();
  for (const s of sources) {
    const prev = bySource.get(s.name);
    const records = (prev?.records ?? 0) + (s.record_count ?? 0);
    if (!prev || (SOURCE_PRIORITY[s.status] ?? 0) >= (SOURCE_PRIORITY[prev.status] ?? 0)) {
      bySource.set(s.name, { status: s.status, records, notes: s.notes ?? prev?.notes ?? "" });
    } else {
      bySource.set(s.name, { ...prev, records });
    }
  }
  return bySource;
}

export function gapsForCollector(id: string, gaps: ManifestGap[] = []): ManifestGap[] {
  return gaps.filter((g) => gapParent(g.name) === id);
}

export function resolveCollectorCoverage(
  id: string,
  bySource: Map<string, { status: string; records: number; notes: string }>,
  gaps: ManifestGap[],
): ResolvedCoverage {
  const src = bySource.get(id);
  const childGaps = gapsForCollector(id, gaps);

  if (src && (src.status === "collected" || src.status === "partial")) {
    if (childGaps.length) {
      return {
        state: "partial",
        records: src.records,
        detail: childGaps.map((g) => g.detail).join(" "),
        gaps: childGaps,
      };
    }
    return {
      state: "collected",
      records: src.records,
      detail: src.notes,
      gaps: [],
    };
  }

  const directGap = gaps.find((g) => g.name === id);
  if (directGap) {
    return {
      state: GAP_TO_STATE[directGap.reason] ?? "not_enabled",
      records: 0,
      detail: directGap.detail,
      gaps: childGaps.length ? childGaps : [directGap],
    };
  }

  if (childGaps.length) {
    const primary = childGaps[0];
    return {
      state: GAP_TO_STATE[primary.reason] ?? "not_enabled",
      records: 0,
      detail: childGaps.map((g) => g.detail).join(" "),
      gaps: childGaps,
    };
  }

  if (src?.status === "empty") {
    return { state: "empty", records: 0, detail: src.notes, gaps: [] };
  }

  if (src?.status === "errored") {
    return { state: "denied", records: 0, detail: src.notes, gaps: [] };
  }

  return {
    state: "not_run",
    records: 0,
    detail: "Collector did not run for this case.",
    gaps: [],
  };
}

export function unmappedGaps(gaps: ManifestGap[], catalogIds: Set<string>): ManifestGap[] {
  return gaps.filter((g) => !catalogIds.has(gapParent(g.name)));
}

/** Coverage states shown as checked in panel header collector chips. */
export const COLLECTOR_CHECKED_STATES: ReadonlySet<CoverageState> = new Set([
  "collected",
  "partial",
]);

const COVERAGE_STATUS_LABELS: Record<CoverageState, string> = {
  collected: "Collected",
  partial: "Partial",
  empty: "No records",
  denied: "Access denied",
  not_enabled: "Not enabled",
  not_run: "Not run",
  planned: "Coming soon",
};

export function isCollectorChecked(state: CoverageState): boolean {
  return COLLECTOR_CHECKED_STATES.has(state);
}

const CLOUDTRAIL_ASPECT_GAP: Record<CloudTrailAspect, string> = {
  data_events: "data_events",
  management_events: "management_events",
  insight_events: "insight_events",
  network_activity: "network_activity",
};

export const CLOUDTRAIL_ASPECT_LABEL: Record<CloudTrailAspect, string> = {
  data_events: "Data Events",
  management_events: "Management events",
  insight_events: "Insight events",
  network_activity: "Network Activity events",
};

/** Panel header chip label — scoped CloudTrail categories avoid the full-trail catalog name. */
export function panelCollectorLabel(
  ref: PanelCollectorRef,
  catalogLabel?: string,
): string {
  if (ref.label) return ref.label;
  if (ref.cloudtrailAspect) {
    return `CloudTrail · ${CLOUDTRAIL_ASPECT_LABEL[ref.cloudtrailAspect]}`;
  }
  return catalogLabel ?? ref.id;
}

/** Parse CloudTrail manifest notes, e.g. ``9263 management (s3_logs), 0 insight, 0 data``. */
export function parseCloudTrailNotes(notes: string): {
  management: number;
  insight: number;
  data: number;
  networkActivity: number;
} | null {
  const management = notes.match(/(\d+)\s+management/i);
  if (!management) return null;
  const insight = notes.match(/(\d+)\s+insight/i);
  const data = notes.match(/(\d+)\s+data/i);
  const networkActivity = notes.match(/(\d+)\s+network-activity/i);
  return {
    management: Number(management[1]),
    insight: Number(insight?.[1] ?? 0),
    data: Number(data?.[1] ?? 0),
    networkActivity: Number(networkActivity?.[1] ?? 0),
  };
}

function gapsForCloudTrailAspect(aspect: CloudTrailAspect, gaps: ManifestGap[]): ManifestGap[] {
  const name = CLOUDTRAIL_ASPECT_GAP[aspect];
  return gaps.filter((g) => g.name === name || g.name.startsWith(`${name}:`));
}

function cloudTrailAspectCount(
  aspect: CloudTrailAspect,
  counts: NonNullable<ReturnType<typeof parseCloudTrailNotes>>,
): number {
  switch (aspect) {
    case "data_events":
      return counts.data;
    case "management_events":
      return counts.management;
    case "insight_events":
      return counts.insight;
    case "network_activity":
      return counts.networkActivity;
  }
}

function resolveCloudTrailAspectCoverage(
  bySource: Map<string, { status: string; records: number; notes: string }>,
  gaps: ManifestGap[],
  aspect: CloudTrailAspect,
): ResolvedCoverage {
  const src = bySource.get("cloudtrail");
  const aspectGaps = gapsForCloudTrailAspect(aspect, gaps);
  const counts = src?.notes ? parseCloudTrailNotes(src.notes) : null;
  const records = counts ? cloudTrailAspectCount(aspect, counts) : 0;
  const label = CLOUDTRAIL_ASPECT_LABEL[aspect];

  if (records > 0) {
    return {
      state: aspectGaps.length ? "partial" : "collected",
      records,
      detail: aspectGaps.length
        ? aspectGaps.map((g) => g.detail).join(" ")
        : `${fmtCount(records)} ${label} in window.`,
      gaps: aspectGaps,
    };
  }

  if (aspectGaps.length) {
    const primary = aspectGaps[0];
    return {
      state: GAP_TO_STATE[primary.reason] ?? "not_enabled",
      records: 0,
      detail: aspectGaps.map((g) => g.detail).join(" "),
      gaps: aspectGaps,
    };
  }

  return {
    state: "not_enabled",
    records: 0,
    detail: `No ${label} in window — enable the event selectors on the trail or widen the time window.`,
    gaps: [],
  };
}

function fmtCount(n: number): string {
  return n.toLocaleString();
}

/** Panel header chips: scoped CloudTrail categories and zero-record collectors stay unchecked. */
export function resolvePanelCollectorCoverage(
  ref: PanelCollectorRef,
  bySource: Map<string, { status: string; records: number; notes: string }>,
  gaps: ManifestGap[],
): ResolvedCoverage {
  if (ref.id === "cloudtrail" && ref.cloudtrailAspect) {
    return resolveCloudTrailAspectCoverage(bySource, gaps, ref.cloudtrailAspect);
  }
  return resolveCollectorCoverage(ref.id, bySource, gaps);
}

/** Checked when the collector yielded records usable by the panel (not merely "ran"). */
export function isPanelCollectorChecked(resolved: ResolvedCoverage): boolean {
  return isCollectorChecked(resolved.state) && resolved.records > 0;
}

export function collectorStatusLabel(state: CoverageState): string {
  return COVERAGE_STATUS_LABELS[state];
}

/** Default note for catalog sources without a Ventra collector yet. */
export const PLANNED_COLLECTOR_NOTE =
  "Coming soon — Ventra does not collect this source yet.";

const LEGACY_PLANNED_COLLECTOR = /Collection not yet supported[^.]*\.?\s*/gi;

/** Normalize posture / gap detail for unbuilt collectors (handles legacy manifest text). */
export function plannedCollectorDetail(detail: string): string {
  const trimmed = detail.trim();
  if (!trimmed) return PLANNED_COLLECTOR_NOTE;
  const withoutLegacy = trimmed.replace(LEGACY_PLANNED_COLLECTOR, "").replace(/\s*[—–-]\s*$/, "").trim();
  if (!withoutLegacy) return PLANNED_COLLECTOR_NOTE;
  if (withoutLegacy.includes(PLANNED_COLLECTOR_NOTE)) return withoutLegacy;
  return `${withoutLegacy} ${PLANNED_COLLECTOR_NOTE}`;
}

/** Coverage states where a Ventra collector could still be run for this case. */
export const ACQUIRABLE_COVERAGE: ReadonlySet<CoverageState> = new Set([
  "not_run",
  "not_enabled",
  "denied",
  "empty",
]);

/** Collectors in the cheat sheet that are missing or incomplete for this case. */
export function missingCollectorIds(
  cloud: Cloud,
  bySource: Map<string, { status: string; records: number; notes: string }>,
  gaps: ManifestGap[],
): string[] {
  const out: string[] = [];
  for (const item of catalogItems(cloud)) {
    if (!IMPLEMENTED_LOG_COLLECTORS.has(item.id)) continue;
    const cov = resolveCollectorCoverage(item.id, bySource, gaps);
    if (ACQUIRABLE_COVERAGE.has(cov.state)) out.push(item.id);
  }
  return out;
}
