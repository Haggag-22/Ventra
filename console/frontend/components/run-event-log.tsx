"use client";

import { displayArtifactLabel } from "@/lib/artifact-icons";
import {
  filterCollectorEvents,
  formatEventTime,
  formatRunEventDisplay,
} from "@/lib/collector-run-log";
import { rowPhase } from "@/lib/run-matrix-stats";
import type { CollectorMatrixRow } from "@/lib/types";
import type { RunStreamEvent } from "@/lib/use-run-matrix";
import { cn } from "@/lib/utils";
import { Terminal, X } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";

const TONE_CLASS: Record<string, string> = {
  default: "text-fg",
  ok: "text-ok-green",
  warn: "text-warn-amber",
  bad: "text-bad-red",
  muted: "text-fg-subtle",
};

export function RunEventLog({
  events,
  filterCollector,
  filterRow,
  live = false,
  onClearFilter,
  className,
}: {
  events: RunStreamEvent[];
  filterCollector?: string | null;
  filterRow?: CollectorMatrixRow;
  live?: boolean;
  onClearFilter?: () => void;
  className?: string;
}) {
  const bodyRef = useRef<HTMLDivElement>(null);
  const prevCountRef = useRef(0);

  const lines = useMemo(() => {
    const filtered = filterCollector
      ? filterCollectorEvents(events, filterCollector)
      : events;

    const display = filtered.map(formatRunEventDisplay);

    if (filterCollector && filterRow) {
      const phase = rowPhase(filterRow.status);
      const liveMsg = filterRow.live_msg?.trim();
      if (liveMsg && (phase === "running" || phase === "pending")) {
        const lastPrimary = display.at(-1)?.primary ?? "";
        if (!lastPrimary.includes(liveMsg)) {
          display.push({
            primary: liveMsg,
            tone: phase === "pending" ? "muted" : "default",
            mono: liveMsg.startsWith("[gcs]"),
          });
        }
      }
    }

    return display;
  }, [events, filterCollector, filterRow]);

  const filterPhase = filterRow ? rowPhase(filterRow.status) : null;

  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const grew = lines.length > prevCountRef.current;
    prevCountRef.current = lines.length;
    if (live && grew) {
      el.scrollTop = el.scrollHeight;
    }
  }, [lines.length, lines.at(-1)?.primary, live]);

  return (
    <div className={cn("run-terminal glass-card", filterCollector && "is-filtered", className)}>
      <div className="run-terminal-header">
        <Terminal className="h-3.5 w-3.5 text-accent" aria-hidden />
        <span className="text-xs font-medium text-fg">
          {filterCollector ? `${displayArtifactLabel(filterCollector)} log` : "Run log"}
        </span>
        {live && (
          <span className="inline-flex items-center gap-1 text-2xs text-ok-green">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-ok-green" />
            live
          </span>
        )}
        <span className="ml-auto text-2xs text-fg-faint">
          {lines.length ? `${lines.length} lines` : "no events yet"}
        </span>
        {filterCollector && onClearFilter && (
          <button
            type="button"
            onClick={onClearFilter}
            className="rounded p-0.5 text-fg-subtle hover:bg-surface-2 hover:text-fg"
            aria-label="Show full run log"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <div
        ref={bodyRef}
        className="run-terminal-body"
        aria-live={live ? "polite" : undefined}
        aria-relevant="additions"
      >
        {lines.length ? (
          lines.map((line, i) => (
            <div
              key={`${line.ts ?? ""}-${line.primary}-${i}`}
              className="run-event-line"
            >
              <span className="run-event-time">[{formatEventTime(line.ts)}]</span>
              <div className="min-w-0 flex-1">
                <p
                  className={cn(
                    "run-event-msg",
                    TONE_CLASS[line.tone],
                    line.mono && "font-mono text-2xs",
                  )}
                >
                  {line.primary}
                </p>
                {line.detail ? (
                  <p className="run-event-detail text-fg-subtle">{line.detail}</p>
                ) : null}
              </div>
            </div>
          ))
        ) : (
          <p className="py-2 text-fg-subtle">
            {filterCollector
              ? filterPhase === "pass" && filterRow
                ? "Collector finished. Select Seal evidence package or Ingest, or clear the filter (×) for the full run log."
                : "No stream events for this step yet."
              : "Waiting for run events…"}
          </p>
        )}
      </div>
    </div>
  );
}
