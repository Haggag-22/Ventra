import type { UnifiedEvent } from "@/lib/types";

/** LookupEvents-shaped record (matches old-gui ``cloudtrail_event`` payload). */
export function toLookupEventRecord(event: UnifiedEvent): Record<string, unknown> {
  const detail = { ...(event.raw ?? {}) } as Record<string, unknown>;
  const ui = (detail.userIdentity as Record<string, unknown> | undefined) ?? {};
  const eventSource = String(
    detail.eventSource ??
      (event.cloud_service ? `${event.cloud_service}.amazonaws.com` : ""),
  );

  return {
    EventId: lookupEventId(event, detail),
    EventName: String(detail.eventName ?? event.event_action ?? ""),
    EventTime: event.timestamp,
    EventSource: eventSource,
    Username: String(ui.userName ?? event.user_name ?? ""),
    ReadOnly: String(detail.readOnly ?? "false"),
    CloudTrailEvent: detail,
  };
}

function lookupEventId(event: UnifiedEvent, detail: Record<string, unknown>): string {
  const raw = detail.eventID ?? detail.EventId;
  if (typeof raw === "string" && raw) return raw;
  return syntheticEventId(`${event.timestamp}:${event.event_action}:${event.user_name}`);
}

function syntheticEventId(seed: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < seed.length; i++) {
    const c = seed.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193);
    h2 = Math.imul(h2 ^ c, 0x01000193);
  }
  const p = (n: number, len: number) => (n >>> 0).toString(16).padStart(len, "0").slice(-len);
  return `${p(h1, 8)}-${p(h1 >>> 8, 4)}-4${p(h2, 3)}-a${p(h2 >>> 4, 3)}-${p(h1 ^ h2, 12)}`;
}

export type JsonHighlightKind = "key" | "str" | "num" | "bool" | "null" | "plain";

export interface JsonHighlightSegment {
  kind: JsonHighlightKind;
  text: string;
}

/** Tokenize JSON for syntax highlighting (ported from old-gui ``highlightJson``). */
export function highlightJsonSegments(obj: unknown): JsonHighlightSegment[] {
  const text = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  const segments: JsonHighlightSegment[] = [];
  let last = 0;

  const re =
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\bnull\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

  for (const match of text.matchAll(re)) {
    const index = match.index ?? 0;
    if (index > last) {
      segments.push({ kind: "plain", text: text.slice(last, index) });
    }

    if (match[1] !== undefined) {
      segments.push({ kind: match[2] ? "key" : "str", text: match[1] });
      if (match[2]) segments.push({ kind: "plain", text: match[2] });
    } else if (match[3] !== undefined) {
      segments.push({ kind: "bool", text: match[3] });
    } else if (match[0] === "null") {
      segments.push({ kind: "null", text: "null" });
    } else if (match[4] !== undefined) {
      segments.push({ kind: "num", text: match[4] });
    }

    last = index + match[0].length;
  }

  if (last < text.length) {
    segments.push({ kind: "plain", text: text.slice(last) });
  }

  return segments;
}

export function shortService(source: string | null | undefined): string {
  if (!source) return "—";
  return source.replace(".amazonaws.com", "").replace(/^aws\./, "") || "—";
}

/** CloudTrail native event category (Management / Insight / Data / Network). */
export type CloudTrailCategory = "Management" | "Insight" | "Data" | "Network";

const CLOUDTRAIL_CATEGORY_LABELS: Record<string, CloudTrailCategory> = {
  Management: "Management",
  Insight: "Insight",
  Data: "Data",
  NetworkActivity: "Network",
};

/** Resolve CloudTrail ``eventCategory`` from the unified event's raw payload. */
export function cloudTrailEventCategory(event: UnifiedEvent): CloudTrailCategory {
  const raw = event.raw ?? {};
  let cat = raw.eventCategory;

  if (!cat && typeof raw.CloudTrailEvent === "object" && raw.CloudTrailEvent !== null) {
    cat = (raw.CloudTrailEvent as Record<string, unknown>).eventCategory;
  }

  if (typeof cat === "string" && cat in CLOUDTRAIL_CATEGORY_LABELS) {
    return CLOUDTRAIL_CATEGORY_LABELS[cat];
  }

  return "Management";
}

export function cloudTrailCategoryClass(category: CloudTrailCategory): string {
  switch (category) {
    case "Insight":
      return "ct-cat-insight";
    case "Data":
      return "ct-cat-data";
    case "Network":
      return "ct-cat-network";
    default:
      return "ct-cat-management";
  }
}
