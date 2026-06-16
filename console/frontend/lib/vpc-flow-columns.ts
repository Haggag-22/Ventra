/** VPC Flow Log table — per-flow network events. */

import type { UnifiedEvent } from "./types";

export type VpcFlowColKey =
  | "timestamp"
  | "action"
  | "source_ip"
  | "dest_ip"
  | "dest_port"
  | "protocol"
  | "bytes"
  | "outcome"
  | "interface"
  | "region";

export interface VpcFlowColumn {
  key: VpcFlowColKey;
  label: string;
  min: number;
  locked?: boolean;
}

export const VPC_FLOW_COLS: VpcFlowColumn[] = [
  { key: "timestamp", label: "Time (UTC)", min: 120, locked: true },
  { key: "action", label: "Action", min: 80 },
  { key: "source_ip", label: "Source IP", min: 120 },
  { key: "dest_ip", label: "Dest IP", min: 120 },
  { key: "dest_port", label: "Dest port", min: 80 },
  { key: "protocol", label: "Protocol", min: 80 },
  { key: "bytes", label: "Bytes", min: 90 },
  { key: "outcome", label: "Outcome", min: 90 },
  { key: "interface", label: "ENI", min: 140 },
  { key: "region", label: "Region", min: 90 },
];

export const DEFAULT_VPC_FLOW_WIDTHS: Record<VpcFlowColKey, number> = {
  timestamp: 190,
  action: 90,
  source_ip: 130,
  dest_ip: 130,
  dest_port: 90,
  protocol: 90,
  bytes: 100,
  outcome: 90,
  interface: 160,
  region: 100,
};

export const VPC_FLOW_WIDTHS_KEY = "ventra.vpc-flow-table.widths";
export const VPC_FLOW_VISIBLE_COLS_KEY = "ventra.vpc-flow-table.visible-cols";

export const ALL_VPC_FLOW_COL_KEYS: VpcFlowColKey[] = VPC_FLOW_COLS.map((c) => c.key);

const PROTOCOL_NAMES: Record<string, string> = {
  "1": "ICMP",
  "6": "TCP",
  "17": "UDP",
  "47": "GRE",
  "50": "ESP",
  "58": "ICMPv6",
};

export function loadVpcFlowWidths(): Record<VpcFlowColKey, number> {
  if (typeof window === "undefined") return DEFAULT_VPC_FLOW_WIDTHS;
  try {
    const raw = localStorage.getItem(VPC_FLOW_WIDTHS_KEY);
    if (!raw) return DEFAULT_VPC_FLOW_WIDTHS;
    return { ...DEFAULT_VPC_FLOW_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_VPC_FLOW_WIDTHS;
  }
}

export function loadVisibleVpcFlowCols(): VpcFlowColKey[] {
  if (typeof window === "undefined") return [...ALL_VPC_FLOW_COL_KEYS];
  try {
    const raw = localStorage.getItem(VPC_FLOW_VISIBLE_COLS_KEY);
    if (!raw) return [...ALL_VPC_FLOW_COL_KEYS];
    const parsed = JSON.parse(raw) as string[];
    const valid = parsed.filter((k): k is VpcFlowColKey =>
      ALL_VPC_FLOW_COL_KEYS.includes(k as VpcFlowColKey),
    );
    return valid.length > 0 ? valid : [...ALL_VPC_FLOW_COL_KEYS];
  } catch {
    return [...ALL_VPC_FLOW_COL_KEYS];
  }
}

export function orderedVisibleVpcFlowCols(visible: VpcFlowColKey[]): VpcFlowColumn[] {
  const set = new Set(visible);
  return VPC_FLOW_COLS.filter((c) => set.has(c.key));
}

export function vpcFlowAction(event: UnifiedEvent): string {
  const raw = event.raw ?? {};
  const fromRaw = String(raw.action ?? "").toUpperCase();
  if (fromRaw) return fromRaw;
  return (event.event_action ?? "flow").toUpperCase();
}

export function vpcFlowProtocol(event: UnifiedEvent): string {
  const raw = event.raw ?? {};
  const num = String(raw.protocol ?? "");
  if (!num) return "—";
  const name = PROTOCOL_NAMES[num];
  return name ? `${name} (${num})` : num;
}

export function vpcFlowInterface(event: UnifiedEvent): string {
  const raw = event.raw ?? {};
  const fromRaw = String(raw.interface_id ?? "");
  if (fromRaw) return fromRaw;
  return event.related_resource?.[0] ?? "";
}

export function vpcFlowActionTone(action: string): string {
  if (action === "REJECT") return "text-bad-red";
  if (action === "ACCEPT") return "text-ok-green";
  return "text-fg-subtle";
}

export function vpcFlowOutcomeTone(outcome: string): string {
  if (outcome === "failure") return "text-bad-red";
  if (outcome === "success") return "text-ok-green";
  return "text-fg-subtle";
}
