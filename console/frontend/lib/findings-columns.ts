/** Findings table column definitions — shared by the toolbar and table. */

export type FindingColKey =
  | "timestamp"
  | "severity"
  | "finding_source"
  | "finding_class"
  | "event_action"
  | "user_name"
  | "source_ip"
  | "cloud_region";

export interface FindingColumn {
  key: FindingColKey;
  label: string;
  min: number;
  locked?: boolean;
}

export const FINDING_COLS: FindingColumn[] = [
  { key: "timestamp", label: "Time (UTC)", min: 120, locked: true },
  { key: "severity", label: "Severity", min: 80 },
  { key: "finding_source", label: "Source", min: 100 },
  { key: "finding_class", label: "Class", min: 100 },
  { key: "event_action", label: "Action", min: 140 },
  { key: "user_name", label: "Principal", min: 120 },
  { key: "source_ip", label: "Source IP", min: 120 },
  { key: "cloud_region", label: "Region", min: 80 },
];

export const ALL_FINDING_COL_KEYS: FindingColKey[] = FINDING_COLS.map((c) => c.key);

export const DEFAULT_FINDING_WIDTHS: Record<FindingColKey, number> = {
  timestamp: 180,
  severity: 88,
  finding_source: 110,
  finding_class: 120,
  event_action: 240,
  user_name: 180,
  source_ip: 160,
  cloud_region: 100,
};

export const FINDING_WIDTHS_KEY = "ventra.findings-table.widths.v2";
export const FINDING_VISIBLE_COLS_KEY = "ventra.findings-table.visible-cols";

export function loadFindingWidths(): Record<FindingColKey, number> {
  if (typeof window === "undefined") return DEFAULT_FINDING_WIDTHS;
  try {
    const raw = localStorage.getItem(FINDING_WIDTHS_KEY);
    if (!raw) return DEFAULT_FINDING_WIDTHS;
    return { ...DEFAULT_FINDING_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_FINDING_WIDTHS;
  }
}

export function loadVisibleFindingCols(): FindingColKey[] {
  if (typeof window === "undefined") return [...ALL_FINDING_COL_KEYS];
  try {
    const raw = localStorage.getItem(FINDING_VISIBLE_COLS_KEY);
    if (!raw) return [...ALL_FINDING_COL_KEYS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is FindingColKey =>
      ALL_FINDING_COL_KEYS.includes(k as FindingColKey),
    );
    return valid.length > 0 ? valid : [...ALL_FINDING_COL_KEYS];
  } catch {
    return [...ALL_FINDING_COL_KEYS];
  }
}

export function orderedVisibleFindingCols(visible: FindingColKey[]): FindingColumn[] {
  const set = new Set(visible);
  return FINDING_COLS.filter((c) => set.has(c.key));
}
