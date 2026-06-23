import {
  AlertOctagon,
  AlertTriangle,
  Info,
  ShieldAlert,
  ShieldQuestion,
  type LucideIcon,
} from "lucide-react";
import type { Integrity, Severity } from "./types";

// Severity is never conveyed by color alone — each level pairs a token color with an icon
// and a label (WCAG: information must not rely on color).
export const SEVERITY_META: Record<
  Severity,
  { label: string; icon: LucideIcon; text: string; bg: string; dot: string; rank: number }
> = {
  critical: {
    label: "Critical",
    icon: ShieldAlert,
    text: "text-critical",
    bg: "bg-critical/12 border-critical/30",
    dot: "bg-critical",
    rank: 5,
  },
  high: {
    label: "High",
    icon: AlertOctagon,
    text: "text-high",
    bg: "bg-high/12 border-high/30",
    dot: "bg-high",
    rank: 4,
  },
  medium: {
    label: "Medium",
    icon: AlertTriangle,
    text: "text-medium",
    bg: "bg-medium/12 border-medium/30",
    dot: "bg-medium",
    rank: 3,
  },
  low: {
    label: "Low",
    icon: Info,
    text: "text-low",
    bg: "bg-low/12 border-low/30",
    dot: "bg-low",
    rank: 2,
  },
  info: {
    label: "Info",
    icon: ShieldQuestion,
    text: "text-info",
    bg: "bg-info/10 border-info/25",
    dot: "bg-info",
    rank: 1,
  },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityHex(sev: Severity): string {
  // Used by SVG charts where we need a concrete color rather than a Tailwind class.
  return {
    critical: "rgb(var(--sev-critical))",
    high: "rgb(var(--sev-high))",
    medium: "rgb(var(--sev-medium))",
    low: "rgb(var(--sev-low))",
    info: "rgb(var(--sev-info))",
  }[sev];
}

// Stable color per event category so charts + tables read consistently.
export const CATEGORY_COLORS: Record<string, string> = {
  authentication: "rgb(96 165 250)",
  iam: "rgb(167 139 250)",
  network: "rgb(45 212 191)",
  configuration: "rgb(251 146 60)",
  data: "rgb(244 114 182)",
  threat: "rgb(244 63 94)",
  session: "rgb(129 140 248)",
  process: "rgb(148 163 184)",
};

export const INTEGRITY_META: Record<
  Integrity,
  { label: string; text: string; dot: string; help: string }
> = {
  green: {
    label: "Verified",
    text: "text-ok-green",
    dot: "bg-ok-green",
    help: "Signature valid and every source hash matched.",
  },
  amber: {
    label: "Partial",
    text: "text-warn-amber",
    dot: "bg-warn-amber",
    help: "Hashes matched but sealed with a non-cryptographic stamp, or an optional source is missing.",
  },
  red: {
    label: "Failed",
    text: "text-bad-red",
    dot: "bg-bad-red",
    help: "A source hash mismatched or the signature failed. Treat evidence with caution.",
  },
  unknown: {
    label: "Unknown",
    text: "text-fg-subtle",
    dot: "bg-fg-subtle",
    help: "Integrity has not been evaluated.",
  },
};
