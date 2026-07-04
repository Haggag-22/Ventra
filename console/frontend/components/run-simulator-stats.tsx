"use client";

import { SeverityBar } from "@/components/charts";
import { Card } from "@/components/ui";
import { fmtNum } from "@/lib/format";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import type { RunMatrixStats } from "@/lib/run-matrix-stats";
import { cn } from "@/lib/utils";
import {
  CheckCircle2,
  Clock,
  Database,
  Loader2,
  PauseCircle,
  Radio,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useRef, type ReactNode } from "react";

const RING_R = 38;
const RING_C = 2 * Math.PI * RING_R;

function ProgressRing({ pct, complete, total }: { pct: number; complete: number; total: number }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const progressRef = useRef<SVGCircleElement>(null);
  const pctLabelRef = useRef<HTMLSpanElement>(null);
  const countLabelRef = useRef<HTMLSpanElement>(null);

  const clampedPct = Math.min(1, Math.max(0, pct));
  const targetOffset = RING_C * (1 - clampedPct);
  const mapOffset = gsap.utils.mapRange(0, 1, RING_C, 0);

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
          const duration = reduceMotion ? 0 : 0.5;

          gsap.to(progressRef.current, {
            strokeDashoffset: targetOffset,
            duration,
            ease: "power2.out",
          });

          const pctObj = { val: reduceMotion ? clampedPct * 100 : 0 };
          gsap.to(pctObj, {
            val: clampedPct * 100,
            duration,
            snap: { val: 1 },
            onUpdate: () => {
              if (pctLabelRef.current) {
                pctLabelRef.current.textContent = `${Math.round(pctObj.val)}%`;
              }
            },
          });

          const countObj = { val: reduceMotion ? complete : 0 };
          gsap.to(countObj, {
            val: complete,
            duration,
            snap: { val: 1 },
            onUpdate: () => {
              if (countLabelRef.current) {
                countLabelRef.current.textContent = `${Math.round(countObj.val)}/${total}`;
              }
            },
          });
        },
        containerRef,
      );
      return () => mm.revert();
    },
    {
      scope: containerRef,
      dependencies: [pct, complete, total],
      revertOnUpdate: true,
    },
  );

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add("(prefers-reduced-motion: no-preference)", () => {
        gsap.set(progressRef.current, { strokeDashoffset: mapOffset(0) });
      }, containerRef);
      return () => mm.revert();
    },
    { scope: containerRef },
  );

  return (
    <div
      ref={containerRef}
      className="relative flex h-[88px] w-[88px] shrink-0 items-center justify-center"
    >
      <svg viewBox="0 0 88 88" className="h-full w-full -rotate-90" aria-hidden>
        <circle
          cx="44"
          cy="44"
          r={RING_R}
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
          className="text-surface-2"
        />
        <circle
          ref={progressRef}
          cx="44"
          cy="44"
          r={RING_R}
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={RING_C}
          strokeDashoffset={RING_C}
          className="text-accent"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          ref={pctLabelRef}
          className="mono text-lg font-semibold tabular-nums text-fg"
        >
          0%
        </span>
        <span ref={countLabelRef} className="text-2xs text-fg-subtle">
          0/{total}
        </span>
      </div>
    </div>
  );
}

function AnimatedCount({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const prevRef = useRef(value);

  useGSAP(
    () => {
      const from = prevRef.current;
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
              if (ref.current) ref.current.textContent = String(Math.round(obj.val));
            },
            onComplete: () => {
              prevRef.current = to;
            },
          });
        },
      );
      return () => mm.revert();
    },
    { scope: ref, dependencies: [value], revertOnUpdate: true },
  );

  return (
    <span ref={ref} className="tabular-nums">
      {value}
    </span>
  );
}

function RunStatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "default",
  animateValue,
}: {
  label: string;
  value?: ReactNode;
  sub?: ReactNode;
  icon?: LucideIcon;
  tone?: "default" | "success" | "danger" | "warn" | "accent" | "muted";
  animateValue?: number;
}) {
  const valueTone =
    tone === "success"
      ? "text-ok-green"
      : tone === "danger"
        ? "text-bad-red"
        : tone === "warn"
          ? "text-warn-amber"
          : tone === "accent"
            ? "text-accent"
            : tone === "muted"
              ? "text-fg-subtle"
              : "text-fg";

  return (
    <Card className="run-stat-card p-3.5">
      <div className="flex items-center justify-between gap-2">
        <span className="stat-label">{label}</span>
        {Icon && <Icon className={cn("h-4 w-4 shrink-0", valueTone, "opacity-80")} />}
      </div>
      <div className={cn("mt-1.5 text-xl font-semibold tabular-nums", valueTone)}>
        {animateValue != null ? <AnimatedCount value={animateValue} /> : value}
      </div>
      {sub && <div className="mt-0.5 text-2xs text-fg-subtle">{sub}</div>}
    </Card>
  );
}

export function RunSimulatorStats({
  stats,
  elapsed,
  live,
  className,
}: {
  stats: RunMatrixStats;
  elapsed: string;
  live?: boolean;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sevTotal = Object.values(stats.severityCounts).reduce((a, b) => a + b, 0);

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
          gsap.from(".run-stat-card", {
            autoAlpha: reduceMotion ? 1 : 0,
            y: reduceMotion ? 0 : 12,
            duration: reduceMotion ? 0 : 0.35,
            stagger: reduceMotion ? 0 : 0.08,
            ease: "power2.out",
          });
        },
        containerRef,
      );
      return () => mm.revert();
    },
    { scope: containerRef, dependencies: [stats.total], revertOnUpdate: false },
  );

  return (
    <div ref={containerRef} className={cn("space-y-4", className)}>
      <div className="flex flex-wrap items-center gap-4">
        <ProgressRing pct={stats.pct} complete={stats.complete} total={stats.total} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-medium text-fg">Collection progress</h2>
            {live && (
              <span className="inline-flex items-center gap-1 rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-2xs font-medium text-accent">
                <Radio className="h-3 w-3 animate-pulse" aria-hidden />
                Live
              </span>
            )}
            {stats.activeCollector && (
              <span className="inline-flex items-center gap-1 text-2xs text-warn-amber">
                <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
                Collecting {stats.activeCollector}
              </span>
            )}
          </div>
          {sevTotal > 0 && (
            <div className="mt-3 max-w-md">
              <p className="mb-1 text-2xs text-fg-subtle">Collected by severity</p>
              <SeverityBar counts={stats.severityCounts} />
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <RunStatCard
          label="Collected"
          animateValue={stats.pass + stats.partial}
          sub={`${fmtNum(stats.totalRecords)} records`}
          icon={CheckCircle2}
          tone="success"
        />
        <RunStatCard
          label="Failed"
          animateValue={stats.fail}
          sub={stats.fail > 0 ? "Review gaps below" : "None"}
          icon={XCircle}
          tone={stats.fail > 0 ? "danger" : "muted"}
        />
        <RunStatCard
          label="In progress"
          animateValue={stats.running}
          sub={stats.activeCollector ?? "—"}
          icon={Loader2}
          tone={stats.running > 0 ? "warn" : "muted"}
        />
        <RunStatCard
          label="Pending"
          animateValue={stats.pending}
          sub="Queued collectors"
          icon={PauseCircle}
          tone="muted"
        />
        <RunStatCard
          label="Elapsed"
          value={elapsed}
          sub={
            <span className="inline-flex items-center gap-1">
              <Database className="h-3 w-3" aria-hidden />
              {stats.complete}/{stats.total} done
            </span>
          }
          icon={Clock}
          tone="accent"
        />
      </div>
    </div>
  );
}
