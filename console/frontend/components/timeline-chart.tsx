"use client";

import { severityHex } from "@/lib/severity";
import type { TimelinePoint } from "@/lib/types";
import { fmtTimeShort } from "@/lib/format";
import { useMemo, useRef, useState } from "react";

interface Props {
  points: TimelinePoint[];
  min: string | null;
  max: string | null;
  onBrush?: (since: string, until: string) => void;
  height?: number;
}

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function TimelineChart({ points, min, max, onBrush, height = 200 }: Props) {
  const ref = useRef<SVGSVGElement>(null);
  const [drag, setDrag] = useState<{ x0: number; x1: number } | null>(null);
  const [hover, setHover] = useState<{ x: number; pt: TimelinePoint } | null>(null);

  const { tMin, tMax, lanes } = useMemo(() => {
    const times = points.map((p) => new Date(p.t).getTime()).filter((n) => !isNaN(n));
    const lo = min ? new Date(min).getTime() : Math.min(...times);
    const hi = max ? new Date(max).getTime() : Math.max(...times);
    const sources = Array.from(new Set(points.map((p) => p.source)));
    return { tMin: lo, tMax: hi || lo + 1, lanes: sources };
  }, [points, min, max]);

  const PAD_L = 92;
  const PAD_R = 16;
  const PAD_T = 8;
  const laneH = Math.max(26, (height - PAD_T - 28) / Math.max(lanes.length, 1));
  const span = tMax - tMin || 1;

  const xOf = (t: string) => {
    const ms = new Date(t).getTime();
    const frac = (ms - tMin) / span;
    return PAD_L + frac * (width() - PAD_L - PAD_R);
  };
  function width() {
    return ref.current?.clientWidth ?? 900;
  }

  const ticks = useMemo(() => {
    const out: { x: number; label: string }[] = [];
    const n = 6;
    for (let i = 0; i <= n; i++) {
      const t = tMin + (span * i) / n;
      out.push({ x: PAD_L + (i / n) * (width() - PAD_L - PAD_R), label: fmtTimeShort(new Date(t).toISOString()) });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tMin, tMax, span]);

  const onDown = (e: React.MouseEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const x = e.clientX - rect.left;
    if (x < PAD_L) return;
    setDrag({ x0: x, x1: x });
  };
  const onMove = (e: React.MouseEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const x = e.clientX - rect.left;
    if (drag) setDrag({ ...drag, x1: x });
  };
  const onUp = () => {
    if (drag && Math.abs(drag.x1 - drag.x0) > 6 && onBrush) {
      const w = width();
      const toTime = (x: number) =>
        new Date(tMin + ((x - PAD_L) / (w - PAD_L - PAD_R)) * span).toISOString();
      const a = Math.min(drag.x0, drag.x1);
      const b = Math.max(drag.x0, drag.x1);
      onBrush(toTime(a).replace(/\.\d+Z$/, "Z"), toTime(b).replace(/\.\d+Z$/, "Z"));
    }
    setDrag(null);
  };

  return (
    <div className="relative select-none">
      <svg
        ref={ref}
        width="100%"
        height={height}
        onMouseDown={onDown}
        onMouseMove={onMove}
        onMouseUp={onUp}
        onMouseLeave={() => {
          setDrag(null);
          setHover(null);
        }}
        className="cursor-crosshair"
      >
        {/* lane backgrounds + labels */}
        {lanes.map((lane, i) => {
          const y = PAD_T + i * laneH;
          return (
            <g key={lane}>
              <rect
                x={PAD_L}
                y={y}
                width={width() - PAD_L - PAD_R}
                height={laneH - 4}
                fill={i % 2 ? "rgb(var(--surface-2))" : "transparent"}
                opacity={0.4}
                rx={4}
              />
              <text x={12} y={y + laneH / 2} dominantBaseline="middle" className="mono"
                fontSize={11} fill="rgb(var(--fg-subtle))">
                {lane}
              </text>
            </g>
          );
        })}

        {/* vertical grid + axis labels */}
        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={t.x} y1={PAD_T} x2={t.x} y2={height - 22} stroke="rgb(var(--border))" strokeWidth={1} opacity={0.5} />
            <text x={t.x} y={height - 6} textAnchor="middle" fontSize={10} fill="rgb(var(--fg-subtle))" className="mono">
              {t.label}
            </text>
          </g>
        ))}

        {/* points */}
        {points.map((p, i) => {
          const laneIdx = lanes.indexOf(p.source);
          const y = PAD_T + laneIdx * laneH + (laneH - 4) / 2;
          const x = xOf(p.t);
          const rank = SEV_RANK[p.severity] ?? 1;
          const rad = 2 + rank * 0.9;
          return (
            <circle
              key={i}
              cx={x}
              cy={y}
              r={rad}
              fill={severityHex(p.severity as any)}
              fillOpacity={rank >= 4 ? 0.95 : 0.6}
              stroke={rank >= 4 ? severityHex(p.severity as any) : "none"}
              strokeWidth={rank >= 4 ? 1 : 0}
              onMouseEnter={() => setHover({ x, pt: p })}
            />
          );
        })}

        {/* brush selection */}
        {drag && (
          <rect
            x={Math.min(drag.x0, drag.x1)}
            y={PAD_T}
            width={Math.abs(drag.x1 - drag.x0)}
            height={height - PAD_T - 22}
            fill="rgb(var(--accent))"
            fillOpacity={0.12}
            stroke="rgb(var(--accent))"
            strokeOpacity={0.5}
          />
        )}
      </svg>

      {hover && (
        <div
          className="pointer-events-none absolute z-20 rounded-md border border-border bg-surface-2 px-2 py-1 text-2xs shadow-pop"
          style={{ left: Math.min(hover.x, width() - 160), top: 4 }}
        >
          <div className="mono text-fg">{fmtTimeShort(hover.pt.t)}</div>
          <div className="text-fg-subtle capitalize">
            {hover.pt.source} · {hover.pt.severity}
          </div>
        </div>
      )}
    </div>
  );
}
