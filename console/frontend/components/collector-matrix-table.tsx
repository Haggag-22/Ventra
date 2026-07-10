"use client";

import { ArtifactIcon } from "@/components/artifact-icon";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { artifactIconCloud } from "@/lib/catalog";
import { fmtNum } from "@/lib/format";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { effectiveRowStatus, rowPhase } from "@/lib/run-matrix-stats";
import type { CollectorMatrixRow } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Database,
  Loader2,
  Minus,
  PauseCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useRef } from "react";
import { Tooltip } from "./ui";

function fmtElapsed(ms?: number | null): string {
  if (ms == null || ms < 0) return "";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const STATUS_META: Record<
  string,
  { label: string; icon: LucideIcon; className: string; spin?: boolean }
> = {
  pass: {
    label: "Pass",
    icon: CheckCircle2,
    className: "text-ok-green bg-ok-green/10 border-ok-green/30",
  },
  ok: {
    label: "Pass",
    icon: CheckCircle2,
    className: "text-ok-green bg-ok-green/10 border-ok-green/30",
  },
  success: {
    label: "Pass",
    icon: CheckCircle2,
    className: "text-ok-green bg-ok-green/10 border-ok-green/30",
  },
  collected: {
    label: "Pass",
    icon: CheckCircle2,
    className: "text-ok-green bg-ok-green/10 border-ok-green/30",
  },
  partial: {
    label: "Partial",
    icon: AlertCircle,
    className: "text-warn-amber bg-warn-amber/10 border-warn-amber/30",
  },
  fail: {
    label: "Fail",
    icon: AlertCircle,
    className: "text-bad-red bg-bad-red/10 border-bad-red/30",
  },
  failed: {
    label: "Fail",
    icon: AlertCircle,
    className: "text-bad-red bg-bad-red/10 border-bad-red/30",
  },
  error: {
    label: "Fail",
    icon: AlertCircle,
    className: "text-bad-red bg-bad-red/10 border-bad-red/30",
  },
  skipped: {
    label: "Skipped",
    icon: Minus,
    className: "text-fg-subtle bg-surface-2 border-border",
  },
  running: {
    label: "Running",
    icon: Loader2,
    className: "text-warn-amber bg-warn-amber/10 border-warn-amber/30",
    spin: true,
  },
  pending: {
    label: "Pending",
    icon: PauseCircle,
    className: "text-fg-subtle bg-surface-2 border-border",
  },
};

function statusMeta(status: string) {
  const key = status.toLowerCase();
  return (
    STATUS_META[key] ?? {
      label: status.replace(/_/g, " "),
      icon: Minus,
      className: "text-fg-subtle bg-surface-2 border-border",
    }
  );
}

function CollectorStatusBadge({ status }: { status: string }) {
  const meta = statusMeta(status);
  const Icon = meta.icon;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-2xs font-semibold capitalize",
        meta.className,
      )}
    >
      <Icon className={cn("h-3 w-3", meta.spin && "animate-spin")} aria-hidden />
      {meta.label}
    </span>
  );
}

function AnimatedRecords({ value, rowName }: { value: number | null | undefined; rowName: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const prevRef = useRef(value ?? null);

  useGSAP(
    () => {
      if (value == null) return;
      const from = prevRef.current ?? 0;
      const to = value;
      if (from === to) return;

      const mm = gsap.matchMedia();
      mm.add(
        {
          reduceMotion: "(prefers-reduced-motion: reduce)",
          motion: "(prefers-reduced-motion: no-preference)",
        },
        (context) => {
          const reduceMotion = matchMediaReduced(context);
          const obj = { val: reduceMotion ? to : from };
          gsap.to(obj, {
            val: to,
            duration: reduceMotion ? 0 : 0.35,
            snap: { val: 1 },
            ease: "power2.out",
            onUpdate: () => {
              if (ref.current) ref.current.textContent = fmtNum(Math.round(obj.val));
            },
            onComplete: () => {
              prevRef.current = to;
            },
          });
        },
      );
      return () => mm.revert();
    },
    { scope: ref, dependencies: [value, rowName], revertOnUpdate: true },
  );

  if (value == null) return null;
  return (
    <span ref={ref} className="mono tabular-nums text-fg">
      {fmtNum(value)}
    </span>
  );
}

function CollectorRowCard({
  row,
  cloud,
  isActive,
  isSelected,
  onSelect,
  runCancelled = false,
}: {
  row: CollectorMatrixRow;
  cloud: string;
  isActive: boolean;
  isSelected: boolean;
  onSelect?: (name: string) => void;
  runCancelled?: boolean;
}) {
  const displayStatus = effectiveRowStatus(row.status, runCancelled);
  const phase = rowPhase(displayStatus);
  const isRunning = phase === "running";
  const liveMsg = row.live_msg?.trim();
  const showSubtext = isRunning && liveMsg ? liveMsg : undefined;

  return (
    <article
      role={onSelect ? "button" : undefined}
      tabIndex={onSelect ? 0 : undefined}
      onClick={onSelect ? () => onSelect(row.name) : undefined}
      onKeyDown={
        onSelect
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelect(row.name);
              }
            }
          : undefined
      }
      className={cn(
        "collector-row-card collector-row-grid",
        phase === "pass" && "is-pass",
        phase === "partial" && "is-partial",
        phase === "fail" && "is-fail",
        isRunning && !runCancelled && "is-running",
        isActive && "is-active",
        isSelected && "is-selected",
        onSelect && "is-clickable",
      )}
    >
      <div className="collector-row-status">
        <CollectorStatusBadge status={displayStatus} />
      </div>
      <div className="collector-row-icon">
        <ArtifactIcon cloud={cloud} collector={row.name} size={24} />
      </div>
      <div className="collector-row-name">
        <h3 className="truncate text-sm font-semibold leading-tight text-fg">
          {displayArtifactLabel(row.name)}
        </h3>
        {showSubtext ? (
          <Tooltip content={showSubtext}>
            <p className="truncate text-2xs leading-tight text-fg-subtle">{showSubtext}</p>
          </Tooltip>
        ) : null}
      </div>
      <div className="collector-row-records">
        <AnimatedRecords value={row.records} rowName={row.name} />
      </div>
      <div className="collector-row-time mono">{fmtElapsed(row.elapsed_ms)}</div>
    </article>
  );
}

export function CollectorMatrixTable({
  rows,
  cloud = "aws",
  activeCollector,
  selectedCollector,
  onSelectCollector,
  complete,
  total,
  runCancelled = false,
  className,
}: {
  rows: CollectorMatrixRow[];
  cloud?: string;
  activeCollector?: string | null;
  selectedCollector?: string | null;
  onSelectCollector?: (name: string) => void;
  complete?: number;
  total?: number;
  runCancelled?: boolean;
  className?: string;
}) {
  const iconCloud = artifactIconCloud(cloud);
  const containerRef = useRef<HTMLDivElement>(null);
  const activeRef = useRef<HTMLDivElement | null>(null);
  const pct =
    complete != null && total != null && total > 0 ? (complete / total) * 100 : null;

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(
        {
          reduceMotion: "(prefers-reduced-motion: reduce)",
          motion: "(prefers-reduced-motion: no-preference)",
        },
        (context) => {
          const reduceMotion = matchMediaReduced(context);
          gsap.from(".collector-row-card", {
            autoAlpha: reduceMotion ? 1 : 0,
            y: reduceMotion ? 0 : 10,
            duration: reduceMotion ? 0 : 0.32,
            stagger: reduceMotion ? 0 : 0.04,
            ease: "power2.out",
          });
        },
        containerRef,
      );
      return () => mm.revert();
    },
    {
      scope: containerRef,
      dependencies: [rows.length],
      revertOnUpdate: true,
    },
  );

  useEffect(() => {
    if (activeCollector && activeRef.current) {
      activeRef.current.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }, [activeCollector]);

  if (!rows.length) {
    return (
      <div
        className={cn(
          "glass-card rounded-lg px-4 py-10 text-center text-sm text-fg-subtle",
          className,
        )}
      >
        Waiting for collector status…
      </div>
    );
  }

  return (
    <div ref={containerRef} className={cn("collector-matrix-panel", className)}>
      <div className="collector-matrix-header">
        <h2 className="text-sm font-medium text-fg">Collectors</h2>
        {pct != null && (
          <div className="flex items-center gap-2">
            <span className="text-2xs tabular-nums text-fg-subtle">
              {complete}/{total}
            </span>
            <div
              className="collector-progress-track"
              role="progressbar"
              aria-valuenow={complete}
              aria-valuemax={total}
            >
              <div
                className="collector-progress-fill"
                style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
              />
            </div>
          </div>
        )}
      </div>

      <div className="collector-row-list">
        <div className="collector-row-columns-header collector-row-grid" aria-hidden>
          <span />
          <span />
          <span />
          <span className="collector-column-label">
            <Database className="h-3 w-3" />
            Records
          </span>
          <span className="collector-column-label">
            <Clock className="h-3 w-3" />
            Time
          </span>
        </div>
        {rows.map((row) => {
          const displayStatus = effectiveRowStatus(row.status, runCancelled);
          const isActive = runCancelled ? false : activeCollector === row.name;
          const isSelected = selectedCollector === row.name;
          return (
            <div
              key={row.name}
              ref={isActive ? activeRef : undefined}
            >
              <CollectorRowCard
                row={row}
                cloud={iconCloud}
                isActive={isActive}
                isSelected={isSelected}
                onSelect={onSelectCollector}
                runCancelled={runCancelled}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
