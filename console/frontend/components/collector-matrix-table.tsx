"use client";

import { fmtNum } from "@/lib/format";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { rowPhase } from "@/lib/run-matrix-stats";
import type { CollectorMatrixRow } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";
import { useEffect, useRef } from "react";

const STATUS_STYLES: Record<string, string> = {
  pending: "text-fg-subtle",
  running: "text-warn-amber",
  pass: "text-ok-green",
  ok: "text-ok-green",
  success: "text-ok-green",
  collected: "text-ok-green",
  partial: "text-warn-amber",
  fail: "text-bad-red",
  skipped: "text-fg-subtle",
  error: "text-bad-red",
  failed: "text-bad-red",
};

const ROW_BG: Record<string, string> = {
  pass: "bg-ok-green/[0.04] hover:bg-ok-green/[0.07]",
  partial: "bg-warn-amber/[0.05] hover:bg-warn-amber/[0.08]",
  fail: "bg-bad-red/[0.04] hover:bg-bad-red/[0.07]",
  running: "bg-warn-amber/[0.06] hover:bg-warn-amber/[0.09]",
  pending: "bg-transparent hover:bg-surface-2/30",
  other: "hover:bg-surface-2/30",
};

function fmtElapsed(ms?: number | null): string {
  if (ms == null || ms < 0) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
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
            duration: reduceMotion ? 0 : 0.4,
            snap: { val: 1 },
            ease: "power2.out",
            onUpdate: () => {
              if (ref.current) ref.current.textContent = fmtNum(Math.round(obj.val));
            },
            onComplete: () => {
              prevRef.current = to;
            },
          });
          if (!reduceMotion) {
            gsap.fromTo(
              ref.current,
              { autoAlpha: 0.6, scale: 1.05 },
              { autoAlpha: 1, scale: 1, duration: 0.3, ease: "power2.out" },
            );
          }
        },
      );
      return () => mm.revert();
    },
    { scope: ref, dependencies: [value, rowName], revertOnUpdate: true },
  );

  if (value == null) return <span className="text-fg-subtle">—</span>;
  return (
    <span ref={ref} className="mono tabular-nums text-fg">
      {fmtNum(value)}
    </span>
  );
}

function StatusCell({ status, rowName }: { status: string; rowName: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const prevStatus = useRef(status);

  useGSAP(
    () => {
      if (prevStatus.current === status) return;
      const mm = gsap.matchMedia();
      mm.add("(prefers-reduced-motion: no-preference)", () => {
        gsap.fromTo(
          ref.current,
          { scale: 0.92, autoAlpha: 0.5 },
          { scale: 1, autoAlpha: 1, duration: 0.25, ease: "power2.out" },
        );
      });
      prevStatus.current = status;
      return () => mm.revert();
    },
    { scope: ref, dependencies: [status, rowName], revertOnUpdate: true },
  );

  const tone = STATUS_STYLES[status.toLowerCase()] ?? "text-fg";
  const isRunning = status.toLowerCase() === "running";
  return (
    <span
      ref={ref}
      className={cn("inline-flex items-center gap-1.5 text-sm font-medium capitalize", tone)}
    >
      {isRunning && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function CollectorMatrixTable({
  rows,
  activeCollector,
  complete,
  total,
  className,
}: {
  rows: CollectorMatrixRow[];
  activeCollector?: string | null;
  complete?: number;
  total?: number;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const activeRef = useRef<HTMLTableRowElement | null>(null);
  const runningPulseRef = useRef<gsap.core.Tween | null>(null);
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
          gsap.from(".matrix-row", {
            autoAlpha: reduceMotion ? 1 : 0,
            y: reduceMotion ? 0 : 8,
            duration: reduceMotion ? 0 : 0.3,
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

  useGSAP(
    () => {
      runningPulseRef.current?.kill();
      const runningRows = gsap.utils.toArray<HTMLElement>(".matrix-row-running", containerRef.current);
      if (!runningRows.length) return;

      const mm = gsap.matchMedia();
      mm.add("(prefers-reduced-motion: no-preference)", () => {
        runningPulseRef.current = gsap.to(runningRows, {
          scale: 1.008,
          duration: 0.9,
          ease: "sine.inOut",
          yoyo: true,
          repeat: -1,
          transformOrigin: "center center",
        });
      });
      return () => {
        runningPulseRef.current?.kill();
        mm.revert();
      };
    },
    { scope: containerRef, dependencies: [rows.map((r) => `${r.name}:${r.status}`).join("|")] },
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
          "rounded-lg border border-border bg-surface px-4 py-10 text-center text-sm text-fg-subtle",
          className,
        )}
      >
        Waiting for collector status…
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={cn("ct-panel overflow-hidden rounded-lg border border-border", className)}
    >
      {pct != null && (
        <div className="h-1 w-full bg-surface-2" role="progressbar" aria-valuenow={complete} aria-valuemax={total}>
          <div
            className="h-full bg-ok-green transition-[width] duration-500 ease-out"
            style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
          />
        </div>
      )}
      <div className="ct-table-wrap overflow-x-auto">
        <table className="ct-table w-full border-collapse text-left text-sm">
          <thead className="sticky top-0 z-10 bg-surface">
            <tr>
              <th className="w-[12%]">Status</th>
              <th className="w-[24%]">Collector</th>
              <th className="w-[10%]">Severity</th>
              <th className="w-[10%]">Records</th>
              <th className="w-[10%]">Time</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const phase = rowPhase(row.status);
              const isActive = activeCollector === row.name;
              const isRunning = phase === "running";
              return (
                <tr
                  key={row.name}
                  ref={isActive ? activeRef : undefined}
                  className={cn(
                    "matrix-row transition-colors duration-200",
                    isRunning && "matrix-row-running",
                    ROW_BG[phase] ?? ROW_BG.other,
                    isActive &&
                      "relative z-[1] shadow-[inset_3px_0_0_0_rgb(var(--warn-amber))] ring-1 ring-warn-amber/30",
                  )}
                >
                  <td>
                    <StatusCell status={row.status} rowName={row.name} />
                  </td>
                  <td className="font-medium text-fg">{row.name}</td>
                  <td className="capitalize text-fg-subtle">{row.severity ?? "—"}</td>
                  <td>
                    <AnimatedRecords value={row.records} rowName={row.name} />
                  </td>
                  <td className="mono text-fg-subtle">{fmtElapsed(row.elapsed_ms)}</td>
                  <td>
                    {row.live_msg ? (
                      <span className="font-medium text-warn-amber">{row.live_msg}</span>
                    ) : (
                      <span className="text-fg-subtle">{row.detail ?? "—"}</span>
                    )}
                    {row.live_msg && row.detail && (
                      <span className="mt-0.5 block truncate text-2xs text-fg-subtle">
                        {row.detail}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
