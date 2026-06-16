/** DNS resolver query log table — one row per Route53 Resolver lookup. */

import type { UnifiedEvent } from "./types";

export type DnsQueryColKey =
  | "timestamp"
  | "domain"
  | "qtype"
  | "rcode"
  | "answer"
  | "client"
  | "instance"
  | "vpc";

export const DNS_QUERY_COLS: { key: DnsQueryColKey; label: string; min: number }[] = [
  { key: "timestamp", label: "Time (UTC)", min: 120 },
  { key: "domain", label: "Domain", min: 200 },
  { key: "qtype", label: "Type", min: 60 },
  { key: "rcode", label: "Response", min: 90 },
  { key: "answer", label: "Answer", min: 120 },
  { key: "client", label: "Client IP", min: 110 },
  { key: "instance", label: "Instance", min: 130 },
  { key: "vpc", label: "VPC", min: 130 },
];

export const DEFAULT_DNS_QUERY_WIDTHS: Record<DnsQueryColKey, number> = {
  timestamp: 190,
  domain: 280,
  qtype: 70,
  rcode: 100,
  answer: 130,
  client: 120,
  instance: 150,
  vpc: 140,
};

export const DNS_QUERY_WIDTHS_KEY = "ventra.dns-query-table.widths";

const FAIL_RCODES = new Set(["NXDOMAIN", "SERVFAIL", "REFUSED"]);

export function loadDnsQueryWidths(): Record<DnsQueryColKey, number> {
  if (typeof window === "undefined") return DEFAULT_DNS_QUERY_WIDTHS;
  try {
    const raw = localStorage.getItem(DNS_QUERY_WIDTHS_KEY);
    if (!raw) return DEFAULT_DNS_QUERY_WIDTHS;
    return { ...DEFAULT_DNS_QUERY_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_DNS_QUERY_WIDTHS;
  }
}

export function dnsQueryType(event: UnifiedEvent): string {
  return event.event_action.replace(/^dns-query:/, "") || "?";
}

export function dnsRcode(event: UnifiedEvent): string {
  const fromMsg = event.message.match(/→ (\w+)/);
  if (fromMsg) return fromMsg[1];
  return String(event.raw?.rcode ?? "");
}

export function dnsQueryFailed(event: UnifiedEvent): boolean {
  if (event.event_outcome === "failure") return true;
  return FAIL_RCODES.has(dnsRcode(event));
}

export function dnsRcodeTone(rcode: string): string {
  if (FAIL_RCODES.has(rcode)) return "text-bad-red";
  if (rcode === "NOERROR") return "text-ok-green";
  return "text-fg-subtle";
}

export function dnsInstanceId(event: UnifiedEvent): string {
  const srcids = event.raw?.srcids as { instance?: string } | undefined;
  if (srcids?.instance) return srcids.instance;
  const related = event.related_resource?.find((r) => r.startsWith("i-"));
  return related ?? "";
}

export function dnsVpcId(event: UnifiedEvent): string {
  const vpc = event.raw?.vpc_id;
  if (typeof vpc === "string" && vpc) return vpc;
  return event.related_resource?.find((r) => r.startsWith("vpc-")) ?? "";
}

/** DGA / tunneling heuristic: very long labels, deep subdomains, or high digit density. */
export function looksSuspiciousDomain(domain: string): boolean {
  if (!domain) return false;
  const labels = domain.split(".");
  const longest = Math.max(...labels.map((l) => l.length));
  const digits = (domain.match(/\d/g) ?? []).length / domain.length;
  return longest >= 25 || labels.length >= 5 || digits > 0.4;
}
