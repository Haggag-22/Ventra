"use client";

import {
  buildCollectorLogLines,
  formatLogLineTime,
} from "@/lib/collector-run-log";
import { rowPhase } from "@/lib/run-matrix-stats";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import type { CollectorMatrixRow } from "@/lib/types";
import type { RunStreamEvent } from "@/lib/use-run-matrix";
import { cn } from "@/lib/utils";
import { ScrollText, X } from "lucide-react";
import { useEffect, useRef } from "react";

const TONE_CLASS: Record<string, string> = {
  default: "text-fg",
  ok: "text-ok-green",
  warn: "text-warn-amber",
  bad: "text-bad-red",
  muted: "text-fg-subtle",
};

export function CollectorLogPanel({
  collector,
  row,
  events,
  onClose,
  className,
}: {
  collector: string;
  row?: CollectorMatrixRow;
  events: RunStreamEvent[];
  onClose?: () => void;
  className?: string;
}) {
  const bodyRef = useRef<HTMLDivElement>(null);
  const phase = row ? rowPhase(row.status) : "pending";
  const lines = buildCollectorLogLines(collector, row, events);
  const isLive = phase === "running";

  useEffect(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines.length, lines.at(-1)?.text]);

  return (
    <div className={cn("collector-log-panel glass-card", className)}>
      <div className="collector-log-header">
        <ScrollText className="h-3.5 w-3.5 text-accent" aria-hidden />
        <span className="text-xs font-medium text-fg">{displayArtifactLabel(collector)}</span>
        <span className="text-2xs capitalize text-fg-subtle">{phase}</span>
        {isLive && (
          <span className="ml-1 inline-flex items-center gap-1 text-2xs text-ok-green">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-ok-green" />
            live
          </span>
        )}
        <span className="ml-auto text-2xs text-fg-faint">{lines.length} lines</span>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="rounded p-0.5 text-fg-subtle hover:bg-surface-2 hover:text-fg"
            aria-label="Close collector logs"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <div ref={bodyRef} className="collector-log-body" aria-live={isLive ? "polite" : undefined}>
        {lines.map((line, i) => (
          <div key={`${line.ts ?? ""}-${line.text}-${i}`} className="collector-log-line">
            <span className="collector-log-time">[{formatLogLineTime(line.ts)}]</span>
            <span className={cn("collector-log-msg", TONE_CLASS[line.tone])}>{line.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
