"use client";

import { severityHex } from "@/lib/severity";
import type { Severity } from "@/lib/types";
import { fmtNum } from "@/lib/format";
import { cn } from "@/lib/utils";

// ---- Donut (severity / category breakdown) ---------------------------------------------

export function Donut({
  data,
  size = 120,
  thickness = 14,
  centerLabel,
  centerValue,
}: {
  data: { label: string; value: number; color: string }[];
  size?: number;
  thickness?: number;
  centerLabel?: string;
  centerValue?: React.ReactNode;
}) {
  const total = data.reduce((a, d) => a + d.value, 0) || 1;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;

  return (
    <div className="flex items-center gap-4">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="rgb(var(--border))"
          strokeWidth={thickness}
        />
        {data.map((d, i) => {
          const len = (d.value / total) * c;
          const seg = (
            <circle
              key={i}
              cx={size / 2}
              cy={size / 2}
              r={r}
              fill="none"
              stroke={d.color}
              strokeWidth={thickness}
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-offset}
              strokeLinecap="butt"
            />
          );
          offset += len;
          return seg;
        })}
      </svg>
      <div className="space-y-1">
        {(centerValue !== undefined || centerLabel) && (
          <div className="mb-2">
            <div className="text-xl font-semibold tabular-nums">{centerValue}</div>
            {centerLabel && <div className="stat-label">{centerLabel}</div>}
          </div>
        )}
        {data.map((d) => (
          <div key={d.label} className="flex items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: d.color }} />
            <span className="capitalize text-fg-subtle">{d.label}</span>
            <span className="mono ml-auto text-fg">{fmtNum(d.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---- Horizontal bars (top principals / IPs) --------------------------------------------

export function HBars({
  data,
  valueFmt = fmtNum,
  onClick,
  emptyLabel = "No data",
}: {
  data: { label: string; value: number; sub?: string }[];
  valueFmt?: (n: number) => string;
  onClick?: (label: string) => void;
  emptyLabel?: string;
}) {
  if (!data.length) return <div className="py-6 text-center text-xs text-fg-subtle">{emptyLabel}</div>;
  const max = Math.max(...data.map((d) => d.value)) || 1;
  return (
    <div className="space-y-1.5">
      {data.map((d) => (
        <button
          key={d.label}
          onClick={() => onClick?.(d.label)}
          className={cn(
            "group block w-full text-left",
            onClick && "cursor-pointer",
          )}
        >
          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="mono truncate text-fg-subtle group-hover:text-fg" title={d.label}>
              {d.label}
            </span>
            <span className="mono shrink-0 text-fg">{valueFmt(d.value)}</span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div
              className="h-full rounded-full bg-accent/70 group-hover:bg-accent transition-all"
              style={{ width: `${(d.value / max) * 100}%` }}
            />
          </div>
        </button>
      ))}
    </div>
  );
}

// ---- Severity sparkbar (compact distribution) ------------------------------------------

export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((a, s) => a + (counts[s] ?? 0), 0) || 1;
  return (
    <div className="flex h-2 w-full overflow-hidden rounded-full bg-surface-2">
      {order.map((s) => {
        const v = counts[s] ?? 0;
        if (!v) return null;
        return (
          <div
            key={s}
            title={`${s}: ${v}`}
            style={{ width: `${(v / total) * 100}%`, background: severityHex(s) }}
          />
        );
      })}
    </div>
  );
}

// ---- Radar (coverage by source family) -------------------------------------------------

export function RadarChart({
  axes,
  size = 220,
}: {
  /** Each axis carries a 0–100 value. */
  axes: { label: string; value: number }[];
  size?: number;
}) {
  const n = axes.length;
  if (n < 3) return null;

  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 24; // leave room for axis labels
  const rings = [0.25, 0.5, 0.75, 1];
  const angleAt = (i: number) => -Math.PI / 2 + (2 * Math.PI * i) / n;
  const pointAt = (i: number, frac: number): [number, number] => [
    cx + r * frac * Math.cos(angleAt(i)),
    cy + r * frac * Math.sin(angleAt(i)),
  ];
  const polygon = (frac: number) => axes.map((_, i) => pointAt(i, frac).join(",")).join(" ");
  const dataPoints = axes.map((ax, i) => pointAt(i, Math.max(0, Math.min(100, ax.value)) / 100));

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      className="overflow-visible"
      role="img"
      aria-label="Coverage by source family"
    >
      {rings.map((f) => (
        <polygon
          key={f}
          points={polygon(f)}
          fill="none"
          stroke="rgb(var(--border))"
          strokeWidth={1}
          opacity={f === 1 ? 0.9 : 0.45}
        />
      ))}
      {axes.map((_, i) => {
        const [x, y] = pointAt(i, 1);
        return (
          <line
            key={i}
            x1={cx}
            y1={cy}
            x2={x}
            y2={y}
            stroke="rgb(var(--border))"
            strokeWidth={1}
            opacity={0.45}
          />
        );
      })}
      <polygon
        points={dataPoints.map((p) => p.join(",")).join(" ")}
        fill="rgb(var(--accent) / 0.16)"
        stroke="rgb(var(--accent))"
        strokeWidth={1.75}
        strokeLinejoin="round"
      />
      {dataPoints.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r={2.6} fill="rgb(var(--accent))" />
      ))}
      {axes.map((ax, i) => {
        const a = angleAt(i);
        const lx = cx + (r + 12) * Math.cos(a);
        const ly = cy + (r + 12) * Math.sin(a);
        const cos = Math.cos(a);
        const anchor = Math.abs(cos) < 0.35 ? "middle" : cos > 0 ? "start" : "end";
        return (
          <text
            key={i}
            x={lx}
            y={ly}
            textAnchor={anchor}
            dominantBaseline="middle"
            fill="rgb(var(--fg-subtle))"
            style={{ fontSize: 10 }}
          >
            {ax.label}
          </text>
        );
      })}
    </svg>
  );
}
