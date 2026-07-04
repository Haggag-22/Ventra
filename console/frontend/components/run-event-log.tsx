"use client";

import type { RunStreamEvent } from "@/lib/use-run-matrix";
import { cn } from "@/lib/utils";
import { Terminal } from "lucide-react";

function fmtEventTime(ts?: string): string {
  if (!ts) return "--:--:--";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts.slice(11, 19) || ts;
  return d.toISOString().slice(11, 19);
}

function formatEventLine(ev: RunStreamEvent): string {
  const collector = ev.collector ?? "run";
  const type = (ev.type ?? "event").toLowerCase();

  if (type === "start") return `${collector} started`;
  if (type === "finish") {
    const status = ev.status ?? "done";
    const rec =
      ev.records != null && ev.records > 0 ? ` · ${ev.records.toLocaleString()} records` : "";
    return `${collector} ${status}${rec}`;
  }
  if (ev.message) return `${collector} · ${ev.message}`;
  return `${collector} · ${type}`;
}

export function RunEventLog({
  events,
  className,
}: {
  events: RunStreamEvent[];
  className?: string;
}) {
  if (!events.length) return null;

  const visible = events.slice(-5);

  return (
    <div
      className={cn(
        "overflow-hidden rounded-lg border border-border bg-[rgb(var(--bg))] font-mono text-2xs",
        className,
      )}
    >
      <div className="flex items-center gap-2 border-b border-border/60 bg-surface-2/40 px-3 py-1.5 text-fg-subtle">
        <Terminal className="h-3.5 w-3.5" aria-hidden />
        <span>Live events</span>
      </div>
      <ul className="max-h-[7.5rem] divide-y divide-border/40 overflow-auto px-3 py-1">
        {visible.map((ev, i) => (
          <li
            key={`${ev.ts ?? i}-${ev.collector ?? ""}-${ev.type ?? ""}`}
            className="flex gap-2 py-1 text-fg-subtle animate-fade-in"
          >
            <span className="shrink-0 text-fg-faint">[{fmtEventTime(ev.ts)}]</span>
            <span className="min-w-0 truncate text-fg">{formatEventLine(ev)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
