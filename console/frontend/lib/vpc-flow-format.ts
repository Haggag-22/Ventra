/** Parse VPC Flow Log v2 fields for the event drawer. */

import type { AccessLogField } from "./access-log-format";

const V2_ORDER = [
  "version",
  "account_id",
  "interface_id",
  "srcaddr",
  "dstaddr",
  "srcport",
  "dstport",
  "protocol",
  "packets",
  "bytes",
  "start",
  "end",
  "action",
  "log_status",
] as const;

const LABELS: Record<string, string> = {
  version: "Version",
  account_id: "Account ID",
  interface_id: "ENI",
  srcaddr: "Source address",
  dstaddr: "Destination address",
  srcport: "Source port",
  dstport: "Destination port",
  protocol: "Protocol",
  packets: "Packets",
  bytes: "Bytes",
  start: "Start (Unix)",
  end: "End (Unix)",
  action: "Action",
  log_status: "Log status",
};

function isEmpty(value: unknown): boolean {
  const s = String(value ?? "");
  return s === "" || s === "-";
}

function parseLine(message: string): Record<string, string> | null {
  const parts = message.trim().split(/\s+/);
  if (parts.length < V2_ORDER.length) return null;
  return Object.fromEntries(V2_ORDER.map((k, i) => [k, parts[i] ?? ""]));
}

export function vpcFlowFields(raw: Record<string, unknown>): AccessLogField[] {
  let flow = raw;
  if (raw.message && !raw.srcaddr) {
    const parsed = parseLine(String(raw.message));
    if (parsed) flow = parsed;
  }

  const fields: AccessLogField[] = [];
  for (const key of V2_ORDER) {
    const value = flow[key];
    if (isEmpty(value)) continue;
    fields.push({ label: LABELS[key] ?? key, value: String(value) });
  }
  return fields;
}
