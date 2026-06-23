/** Kubernetes audit table column definitions — shared by the toolbar and table. */

export type K8sAuditColKey =
  | "timestamp"
  | "event_action"
  | "user_name"
  | "source_ip"
  | "resource_id"
  | "event_outcome"
  | "event_severity"
  | "cloud_region";

export interface K8sAuditColumn {
  key: K8sAuditColKey;
  label: string;
  min: number;
  locked?: boolean;
}

export const K8S_AUDIT_COLS: K8sAuditColumn[] = [
  { key: "timestamp", label: "Time (UTC)", min: 120, locked: true },
  { key: "event_action", label: "Action", min: 140 },
  { key: "user_name", label: "User", min: 90 },
  { key: "source_ip", label: "Source IP", min: 100 },
  { key: "resource_id", label: "Resource", min: 120 },
  { key: "event_outcome", label: "Outcome", min: 80 },
  { key: "event_severity", label: "Severity", min: 80 },
  { key: "cloud_region", label: "Region", min: 80 },
];

export const ALL_K8S_AUDIT_COL_KEYS: K8sAuditColKey[] = K8S_AUDIT_COLS.map((c) => c.key);

export const DEFAULT_K8S_AUDIT_WIDTHS: Record<K8sAuditColKey, number> = {
  timestamp: 190,
  event_action: 220,
  user_name: 140,
  source_ip: 120,
  resource_id: 180,
  event_outcome: 90,
  event_severity: 90,
  cloud_region: 100,
};

export const K8S_AUDIT_WIDTHS_KEY = "ventra.k8s-audit-table.widths";
export const K8S_AUDIT_VISIBLE_COLS_KEY = "ventra.k8s-audit-table.visible-cols";

export function loadK8sAuditWidths(): Record<K8sAuditColKey, number> {
  if (typeof window === "undefined") return DEFAULT_K8S_AUDIT_WIDTHS;
  try {
    const raw = localStorage.getItem(K8S_AUDIT_WIDTHS_KEY);
    if (!raw) return DEFAULT_K8S_AUDIT_WIDTHS;
    return { ...DEFAULT_K8S_AUDIT_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_K8S_AUDIT_WIDTHS;
  }
}

export function loadVisibleK8sAuditCols(): K8sAuditColKey[] {
  if (typeof window === "undefined") return [...ALL_K8S_AUDIT_COL_KEYS];
  try {
    const raw = localStorage.getItem(K8S_AUDIT_VISIBLE_COLS_KEY);
    if (!raw) return [...ALL_K8S_AUDIT_COL_KEYS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is K8sAuditColKey =>
      ALL_K8S_AUDIT_COL_KEYS.includes(k as K8sAuditColKey),
    );
    return valid.length > 0 ? valid : [...ALL_K8S_AUDIT_COL_KEYS];
  } catch {
    return [...ALL_K8S_AUDIT_COL_KEYS];
  }
}

export function orderedVisibleK8sCols(visible: K8sAuditColKey[]): K8sAuditColumn[] {
  const set = new Set(visible);
  return K8S_AUDIT_COLS.filter((c) => set.has(c.key));
}
