import { displayArtifactLabel } from "@/lib/artifact-icons";
import { rowPhase } from "@/lib/run-matrix-stats";
import type { CollectorMatrixRow } from "@/lib/types";
import type { RunStreamEvent } from "@/lib/use-run-matrix";

export interface CollectorLogLine {
  ts?: string;
  text: string;
  tone: "default" | "ok" | "warn" | "bad" | "muted";
}

export interface RunEventDisplay {
  ts?: string;
  collector?: string;
  primary: string;
  detail?: string;
  tone: CollectorLogLine["tone"];
  mono?: boolean;
}

const RUN_EVENT_KEYS = new Set([
  "type",
  "collector",
  "message",
  "status",
  "records",
  "ts",
  "account_id",
  "case_id",
  "regions",
  "collectors",
  "plan_label",
  "preflight_lines",
]);

export function formatEventTime(ts?: string): string {
  if (!ts) return "--:--:--";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts.slice(11, 19) || ts;
  return d.toISOString().slice(11, 19);
}

export function eventTone(ev: RunStreamEvent): CollectorLogLine["tone"] {
  const type = (ev.type ?? "").toLowerCase();
  const status = (ev.status ?? "").toLowerCase();
  if (type === "error" || type === "failed" || type === "ingest_error") return "bad";
  if (type === "cancelled") return "warn";
  if (type === "finish" && ["fail", "failed", "error", "skipped"].includes(status)) return "bad";
  if (
    type === "finish" &&
    ["pass", "ok", "success", "collected", "partial"].includes(status)
  ) {
    return "ok";
  }
  if (type === "completed" || type === "ingested") return "ok";
  if (type === "start" || type === "running" || type === "cancelling") return "warn";
  if (type === "debug") return "muted";
  return "default";
}

function collectorLabel(name?: string): string {
  if (!name || name === "run") return "run";
  return displayArtifactLabel(name);
}

function extraFields(ev: RunStreamEvent): string | undefined {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(ev)) {
    if (RUN_EVENT_KEYS.has(key) || value == null || value === "") continue;
    if (Array.isArray(value)) {
      if (value.length) parts.push(`${key}=${JSON.stringify(value)}`);
      continue;
    }
    if (typeof value === "object") {
      parts.push(`${key}=${JSON.stringify(value)}`);
      continue;
    }
    parts.push(`${key}=${String(value)}`);
  }
  return parts.length ? parts.join(" · ") : undefined;
}

export function formatRunEventDisplay(ev: RunStreamEvent): RunEventDisplay {
  const type = (ev.type ?? "event").toLowerCase();
  const collector = ev.collector as string | undefined;
  const label = collectorLabel(collector);
  const tone = eventTone(ev);

  if (type === "begin_run") {
    const regions = Array.isArray(ev.regions) ? (ev.regions as string[]).join(", ") : "";
    const collectors = Array.isArray(ev.collectors) ? (ev.collectors as string[]).length : 0;
    return {
      ts: ev.ts,
      collector,
      primary: `Run started · account ${String(ev.account_id ?? "—")}`,
      detail: [
        ev.case_id ? `case ${String(ev.case_id)}` : "",
        regions ? `regions ${regions}` : "",
        collectors ? `${collectors} collectors` : "",
        ev.plan_label ? String(ev.plan_label) : "",
      ]
        .filter(Boolean)
        .join(" · "),
      tone: "default",
    };
  }

  if (type === "start") {
    return { ts: ev.ts, collector, primary: `${label} · started`, tone: "warn" };
  }

  if (type === "finish") {
    const status = String(ev.status ?? "done");
    const rec =
      ev.records != null && Number(ev.records) > 0
        ? ` · ${Number(ev.records).toLocaleString()} records`
        : "";
    return {
      ts: ev.ts,
      collector,
      primary: `${label} · ${status}${rec}`,
      detail: ev.message ? String(ev.message) : extraFields(ev),
      tone,
    };
  }

  if (type === "event" && ev.message) {
    return {
      ts: ev.ts,
      collector,
      primary: `${label} · ${String(ev.message)}`,
      tone,
    };
  }

  if (type === "debug" && ev.message) {
    return {
      ts: ev.ts,
      collector,
      primary: String(ev.message),
      tone: "muted",
      mono: true,
    };
  }

  if (type === "error" || type === "ingest_error") {
    return {
      ts: ev.ts,
      collector,
      primary: type === "error" ? "Run error" : "Ingest error",
      detail: ev.message ? String(ev.message) : extraFields(ev),
      tone: "bad",
    };
  }

  if (type === "completed" || type === "cancelled" || type === "failed" || type === "ingested") {
    return {
      ts: ev.ts,
      collector,
      primary: `Run ${type}`,
      detail: ev.message ? String(ev.message) : extraFields(ev),
      tone,
    };
  }

  if (ev.message) {
    return {
      ts: ev.ts,
      collector,
      primary: `${label} · ${String(ev.message)}`,
      detail: extraFields(ev),
      tone,
    };
  }

  return {
    ts: ev.ts,
    collector,
    primary: collector ? `${label} · ${type}` : type,
    detail: extraFields(ev),
    tone,
  };
}

export function filterCollectorEvents(
  events: RunStreamEvent[],
  collector: string,
): RunStreamEvent[] {
  return events.filter((ev) => ev.collector === collector);
}

function formatStreamEvent(ev: RunStreamEvent): CollectorLogLine {
  const display = formatRunEventDisplay(ev);
  const text = display.detail ? `${display.primary} — ${display.detail}` : display.primary;
  return { ts: display.ts, text, tone: display.tone };
}

export function buildCollectorLogLines(
  collector: string,
  row: CollectorMatrixRow | undefined,
  events: RunStreamEvent[],
): CollectorLogLine[] {
  const phase = row ? rowPhase(row.status) : "pending";
  const collectorEvents = filterCollectorEvents(events, collector).filter(
    (ev) => (ev.type ?? "").toLowerCase() !== "begin_run",
  );

  if (phase === "pending" && !collectorEvents.length) {
    const live = row?.live_msg?.trim();
    if (live) {
      return [{ text: live, tone: "muted" }];
    }
    return [{ text: "Not started yet", tone: "muted" }];
  }

  const lines = collectorEvents.map(formatStreamEvent);

  if (phase === "running") {
    const live = row?.live_msg?.trim();
    if (live) {
      const lastText = lines.at(-1)?.text;
      if (lastText !== live) {
        lines.push({ text: live, tone: "default" });
      }
    } else if (!lines.length) {
      lines.push({ text: "Started — waiting for log output…", tone: "warn" });
    }
  }

  if (!lines.length && phase === "fail" && row?.detail?.trim()) {
    lines.push({ text: row.detail.trim(), tone: "bad" });
  }

  return lines;
}

export function formatLogLineTime(ts?: string): string {
  return formatEventTime(ts);
}

export function runEventKey(ev: RunStreamEvent): string {
  return [
    ev.ts ?? "",
    ev.type ?? "",
    ev.collector ?? "",
    ev.message ?? "",
    ev.status ?? "",
    ev.records ?? "",
  ].join("|");
}

export function mergeRunEvents(
  base: RunStreamEvent[],
  incoming: RunStreamEvent[],
): RunStreamEvent[] {
  const seen = new Set(base.map(runEventKey));
  const merged = [...base];
  for (const ev of incoming) {
    const key = runEventKey(ev);
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(ev);
  }
  return merged;
}
