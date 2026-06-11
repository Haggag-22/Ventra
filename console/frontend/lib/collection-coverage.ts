// Collection Coverage helpers — profile scope, gap roll-up, and manifest resolution.

import { CATALOG, type CatalogItem, type Cloud } from "./catalog";

/** Collectors selected by each built-in profile (mirrors collector/common/profiles/*.yml). */
export const PROFILE_COLLECTORS: Record<string, string[]> = {
  baseline: ["account", "cloudtrail", "vpc_flow", "guardduty", "waf", "iam", "sts"],
  full: [
    "account",
    "cloudtrail",
    "vpc_flow",
    "guardduty",
    "waf",
    "iam",
    "sts",
    "config",
    "securityhub",
    "macie",
    "detective",
    "kms",
    "secrets",
    "ec2",
    "s3",
    "lambda",
  ],
  identity: ["account", "cloudtrail", "iam", "kms", "secrets"],
  data_exfil: ["account", "cloudtrail", "vpc_flow", "s3", "lambda"],
  insider: ["account", "cloudtrail", "iam", "sts", "s3"],
  ransomware: ["account", "cloudtrail", "kms", "s3", "ec2", "iam"],
};

/** Sub-artifact / category gaps rolled up to a catalog collector id. */
export const GAP_PARENT: Record<string, string> = {
  cloudtrail_s3: "cloudtrail",
  cloudtrail_config: "cloudtrail",
  insight_events: "cloudtrail",
  data_events: "cloudtrail",
  network_activity: "cloudtrail",
};

export type CoverageState =
  | "collected"
  | "partial"
  | "empty"
  | "denied"
  | "not_enabled"
  | "not_run"
  | "not_in_profile";

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
  inProfile: boolean;
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

export function profileCollectorIds(profileName?: string): string[] {
  if (!profileName) return PROFILE_COLLECTORS.baseline;
  return PROFILE_COLLECTORS[profileName] ?? [];
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
  return gaps.filter((g) => (GAP_PARENT[g.name] ?? g.name) === id);
}

export function resolveCollectorCoverage(
  id: string,
  bySource: Map<string, { status: string; records: number; notes: string }>,
  gaps: ManifestGap[],
  inProfile: boolean,
): ResolvedCoverage {
  if (!inProfile) {
    const src = bySource.get(id);
    if (src && (src.status === "collected" || src.status === "partial")) {
      const childGaps = gapsForCollector(id, gaps);
      return {
        state: childGaps.length ? "partial" : "collected",
        records: src.records,
        detail: src.notes,
        gaps: childGaps,
        inProfile: false,
      };
    }
    return {
      state: "not_in_profile",
      records: 0,
      detail: "Not part of the collection profile that ran.",
      gaps: [],
      inProfile: false,
    };
  }

  const src = bySource.get(id);
  const childGaps = gapsForCollector(id, gaps);

  if (src && (src.status === "collected" || src.status === "partial")) {
    if (childGaps.length) {
      return {
        state: "partial",
        records: src.records,
        detail: childGaps.map((g) => g.detail).join(" "),
        gaps: childGaps,
        inProfile: true,
      };
    }
    return {
      state: "collected",
      records: src.records,
      detail: src.notes,
      gaps: [],
      inProfile: true,
    };
  }

  const directGap = gaps.find((g) => g.name === id);
  if (directGap) {
    return {
      state: GAP_TO_STATE[directGap.reason] ?? "not_enabled",
      records: 0,
      detail: directGap.detail,
      gaps: childGaps.length ? childGaps : directGap ? [directGap] : [],
      inProfile: true,
    };
  }

  if (childGaps.length) {
    const primary = childGaps[0];
    return {
      state: GAP_TO_STATE[primary.reason] ?? "not_enabled",
      records: 0,
      detail: childGaps.map((g) => g.detail).join(" "),
      gaps: childGaps,
      inProfile: true,
    };
  }

  if (src?.status === "empty") {
    return {
      state: "empty",
      records: 0,
      detail: src.notes,
      gaps: [],
      inProfile: true,
    };
  }

  if (src?.status === "errored") {
    return {
      state: "denied",
      records: 0,
      detail: src.notes,
      gaps: [],
      inProfile: true,
    };
  }

  return {
    state: "not_run",
    records: 0,
    detail: "Collector did not run for this case.",
    gaps: [],
    inProfile: true,
  };
}

export function unmappedGaps(gaps: ManifestGap[], catalogIds: Set<string>): ManifestGap[] {
  return gaps.filter((g) => {
    const parent = GAP_PARENT[g.name] ?? g.name;
    return !catalogIds.has(parent);
  });
}
