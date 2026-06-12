// Logs coverage helpers — gap roll-up and manifest resolution.

import { CATALOG, type CatalogItem, type Cloud } from "./catalog";

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
  "cloudtrail",
  "config",
  "vpc_flow",
  "guardduty",
  "securityhub",
  "detective",
  "inspector2",
  "macie",
  "waf",
  "elb_alb",
  "cloudfront",
  "s3_access",
  "route53_resolver",
  "eks_audit",
]);

const AWS_LOGS_BASELINE = new Set([
  "cloudtrail",
  "config",
  "vpc_flow",
  "guardduty",
  "waf",
]);

export function baselineCollectorIds(cloud: Cloud): string[] {
  const items = catalogItems(cloud);
  if (cloud === "aws") {
    return items.filter((i) => AWS_LOGS_BASELINE.has(i.id)).map((i) => i.id);
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
