"use client";

import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";
import { Card } from "./ui";

/** Segmented pill progress bar (4 segments = 25% each). */
export function SegmentedProgress({
  value,
  segments = 4,
  className,
}: {
  value: number;
  segments?: number;
  className?: string;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  const filledCount = Math.floor((clamped / 100) * segments);
  const partialPct = ((clamped / 100) * segments - filledCount) * 100;

  return (
    <div
      className={cn("segmented-progress", className)}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      {Array.from({ length: segments }, (_, i) => {
        const isFilled = i < filledCount;
        const isPartial = i === filledCount && partialPct > 0;
        return (
          <div
            key={i}
            className={cn(
              "segmented-progress-segment",
              isFilled && "is-filled",
              isPartial && "is-partial",
            )}
            style={isPartial ? ({ "--fill-pct": `${partialPct}%` } as React.CSSProperties) : undefined}
          />
        );
      })}
    </div>
  );
}

/** KPI metric card with optional CSS sparkline bars. */
export function KpiMetricCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "default",
  sparkline,
  onClick,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon?: LucideIcon;
  tone?: "default" | "critical" | "high" | "accent" | "cta" | "success";
  /** Heights 0–100 for each bar in the mini chart */
  sparkline?: number[];
  onClick?: () => void;
}) {
  const toneText =
    tone === "critical"
      ? "text-critical"
      : tone === "high"
        ? "text-high"
        : tone === "accent"
          ? "text-accent"
          : tone === "cta"
            ? "text-accent-cta"
            : tone === "success"
              ? "text-ok-green"
              : "text-fg";

  return (
    <div
      className={cn(
        "glass-card glass-card-glow p-4 transition-colors",
        onClick && "cursor-pointer hover:border-accent/20",
      )}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      <div className="stat-card-header justify-between">
        <span className="stat-label">{label}</span>
        {Icon && <Icon className="h-4 w-4 shrink-0 text-fg-faint" aria-hidden />}
      </div>
      <div className={cn("mt-2 text-2xl font-semibold tabular-nums tracking-tight", toneText)}>
        {value}
      </div>
      {sub && <div className="mt-1 text-xs text-fg-subtle">{sub}</div>}
      {sparkline && sparkline.length > 0 && (
        <div
          className={cn("kpi-sparkline", tone === "cta" && "kpi-sparkline--cta")}
          aria-hidden
        >
          {sparkline.map((h, i) => (
            <span
              key={i}
              className="kpi-sparkline-bar"
              style={{ height: `${Math.max(8, Math.min(100, h))}%` }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "default",
  onClick,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon?: LucideIcon;
  tone?: "default" | "critical" | "high" | "accent";
  onClick?: () => void;
}) {
  const toneText =
    tone === "critical"
      ? "text-critical"
      : tone === "high"
        ? "text-high"
        : tone === "accent"
          ? "text-accent"
          : "text-fg";
  return (
    <Card
      className={cn("p-4", onClick && "cursor-pointer hover:border-accent/30 transition-colors")}
      onClick={onClick}
    >
      <div className="stat-card-header justify-between">
        <span className="stat-label">{label}</span>
        {Icon && <Icon className="h-4 w-4 shrink-0 text-fg-subtle" />}
      </div>
      <div className={cn("mt-2 text-2xl font-semibold tabular-nums", toneText)}>{value}</div>
      {sub && <div className="mt-1 text-xs text-fg-subtle">{sub}</div>}
    </Card>
  );
}
