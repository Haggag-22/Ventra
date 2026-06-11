/** CloudTrail table column definitions — shared by the toolbar and table. */

export const CLOUDTRAIL_COLS = [
  { key: "timestamp", label: "Time (UTC)", min: 120, locked: true },
  { key: "event_action", label: "Event", min: 140 },
  { key: "user_name", label: "Principal", min: 90 },
  { key: "source_ip", label: "Source IP", min: 100 },
  { key: "cloud_region", label: "Region", min: 80 },
  { key: "cloud_service", label: "Service", min: 70 },
  { key: "event_category", label: "Category", min: 90 },
] as const;

export type CloudTrailColKey = (typeof CLOUDTRAIL_COLS)[number]["key"];

export const ALL_CLOUDTRAIL_COL_KEYS: CloudTrailColKey[] = CLOUDTRAIL_COLS.map((c) => c.key);

export const DEFAULT_CLOUDTRAIL_WIDTHS: Record<CloudTrailColKey, number> = {
  timestamp: 190,
  event_action: 260,
  user_name: 130,
  source_ip: 130,
  cloud_region: 110,
  cloud_service: 90,
  event_category: 110,
};

export const CLOUDTRAIL_WIDTHS_KEY = "harbor.cloudtrail-table.widths";
export const CLOUDTRAIL_VISIBLE_COLS_KEY = "harbor.cloudtrail-table.visible-cols";

export function loadCloudTrailWidths(): Record<CloudTrailColKey, number> {
  if (typeof window === "undefined") return DEFAULT_CLOUDTRAIL_WIDTHS;
  try {
    const raw = localStorage.getItem(CLOUDTRAIL_WIDTHS_KEY);
    if (!raw) return DEFAULT_CLOUDTRAIL_WIDTHS;
    return { ...DEFAULT_CLOUDTRAIL_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_CLOUDTRAIL_WIDTHS;
  }
}

export function loadVisibleCloudTrailCols(): CloudTrailColKey[] {
  if (typeof window === "undefined") return [...ALL_CLOUDTRAIL_COL_KEYS];
  try {
    const raw = localStorage.getItem(CLOUDTRAIL_VISIBLE_COLS_KEY);
    if (!raw) return [...ALL_CLOUDTRAIL_COL_KEYS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is CloudTrailColKey =>
      ALL_CLOUDTRAIL_COL_KEYS.includes(k as CloudTrailColKey),
    );
    return valid.length > 0 ? valid : [...ALL_CLOUDTRAIL_COL_KEYS];
  } catch {
    return [...ALL_CLOUDTRAIL_COL_KEYS];
  }
}

export function orderedVisibleCols(visible: CloudTrailColKey[]): typeof CLOUDTRAIL_COLS[number][] {
  const set = new Set(visible);
  return CLOUDTRAIL_COLS.filter((c) => set.has(c.key));
}
