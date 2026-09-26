/** CloudTrail table column definitions — shared by the toolbar and table. */

export type CloudTrailColKey =
  | "timestamp"
  | "event_action"
  | "message"
  | "user_name"
  | "source_ip"
  | "cloud_region"
  | "cloud_service"
  | "event_category";

export interface CloudTrailColumn {
  key: CloudTrailColKey;
  label: string;
  /** Backend field the header sorts by; omitted for derived columns. */
  sortField?: string;
  min: number;
  locked?: boolean;
}

export const CLOUDTRAIL_COLS: CloudTrailColumn[] = [
  { key: "timestamp", label: "Time (UTC)", min: 120, sortField: "timestamp", locked: true },
  { key: "event_action", label: "Event", min: 140, sortField: "event_action" },
  { key: "message", label: "Message", min: 200, sortField: "message" },
  { key: "user_name", label: "Principal", min: 90, sortField: "user_name" },
  { key: "source_ip", label: "Source IP", min: 100, sortField: "source_ip" },
  { key: "cloud_region", label: "Region", min: 80, sortField: "cloud_region" },
  { key: "cloud_service", label: "Service", min: 70, sortField: "cloud_service" },
  { key: "event_category", label: "Category", min: 90 },
];

export const ALL_CLOUDTRAIL_COL_KEYS: CloudTrailColKey[] = CLOUDTRAIL_COLS.map((c) => c.key);

/** Default CloudTrail timeline columns (message is optional / CloudWatch-oriented). */
export const DEFAULT_CLOUDTRAIL_VISIBLE_COLS: CloudTrailColKey[] = [
  "timestamp",
  "event_action",
  "user_name",
  "source_ip",
  "cloud_region",
  "cloud_service",
  "event_category",
];

/** Default CloudWatch Logs table — message is the differentiator. */
export const DEFAULT_CLOUDWATCH_VISIBLE_COLS: CloudTrailColKey[] = [
  "timestamp",
  "message",
  "cloud_region",
];

export const DEFAULT_CLOUDTRAIL_WIDTHS: Record<CloudTrailColKey, number> = {
  timestamp: 190,
  event_action: 260,
  message: 520,
  user_name: 130,
  source_ip: 130,
  cloud_region: 110,
  cloud_service: 90,
  event_category: 110,
};

export const CLOUDTRAIL_WIDTHS_KEY = "ventra.cloudtrail-table.widths";
export const CLOUDTRAIL_VISIBLE_COLS_KEY = "ventra.cloudtrail-table.visible-cols";
export const CLOUDWATCH_VISIBLE_COLS_KEY = "ventra.cloudwatch-table.visible-cols";

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
  if (typeof window === "undefined") return [...DEFAULT_CLOUDTRAIL_VISIBLE_COLS];
  try {
    const raw = localStorage.getItem(CLOUDTRAIL_VISIBLE_COLS_KEY);
    if (!raw) return [...DEFAULT_CLOUDTRAIL_VISIBLE_COLS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is CloudTrailColKey =>
      ALL_CLOUDTRAIL_COL_KEYS.includes(k as CloudTrailColKey),
    );
    return valid.length > 0 ? valid : [...DEFAULT_CLOUDTRAIL_VISIBLE_COLS];
  } catch {
    return [...DEFAULT_CLOUDTRAIL_VISIBLE_COLS];
  }
}

export function loadVisibleCloudWatchCols(): CloudTrailColKey[] {
  if (typeof window === "undefined") return [...DEFAULT_CLOUDWATCH_VISIBLE_COLS];
  try {
    const raw = localStorage.getItem(CLOUDWATCH_VISIBLE_COLS_KEY);
    if (!raw) return [...DEFAULT_CLOUDWATCH_VISIBLE_COLS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is CloudTrailColKey =>
      ALL_CLOUDTRAIL_COL_KEYS.includes(k as CloudTrailColKey),
    );
    return valid.length > 0 ? valid : [...DEFAULT_CLOUDWATCH_VISIBLE_COLS];
  } catch {
    return [...DEFAULT_CLOUDWATCH_VISIBLE_COLS];
  }
}

export function orderedVisibleCols(visible: CloudTrailColKey[]): CloudTrailColumn[] {
  const set = new Set(visible);
  return CLOUDTRAIL_COLS.filter((c) => set.has(c.key));
}
