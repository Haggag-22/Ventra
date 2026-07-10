"use client";

import { Card } from "@/components/ui";
import { fmtNum } from "@/lib/format";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import type { RunMatrixStats } from "@/lib/run-matrix-stats";
import { cn } from "@/lib/utils";
import {
  CheckCircle2,
  Clock,
  Database,
  PauseCircle,
  Radio,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useRef, type ReactNode } from "react";

const RING_R = 40;
const RING_C = 2 * Math.PI * RING_R;

function ProgressRing({
  pct,
  complete,
  total,
  tone = "success",
}: {
  pct: number;
  complete: number;
  total: number;
  tone?: "success" | "warn" | "danger";
}) {
  const ringColor =
    tone === "danger" ? "text-bad-red" : tone === "warn" ? "text-warn-amber" : "text-ok-green";
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
      className="relative flex h-[96px] w-[96px] shrink-0 items-center justify-center"
      aria-label={`Collection progress ${Math.round(clampedPct * 100)} percent`}
    >
      <svg viewBox="0 0 96 96" className="h-full w-full -rotate-90" aria-hidden>
        <circle
          cx="48"
          cy="48"
          r={RING_R}
          fill="none"
          stroke="currentColor"
          strokeWidth="5"
          className="text-surface-2"
        />
        <circle
          ref={progressRef}
          cx="48"
          cy="48"
          r={RING_R}
          fill="none"
          stroke="currentColor"
          strokeWidth="5"
          strokeLinecap="round"
          strokeDasharray={RING_C}
          strokeDashoffset={RING_C}
          className={ringColor}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          ref={pctLabelRef}
          className="mono text-lg font-semibold tabular-nums text-fg"
        >
          0%
        </span>
        <span ref={countLabelRef} className="text-2xs tabular-nums text-fg-subtle">
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
    <div className="run-stat-card">
      <div className="stat-card-header justify-between">
        <span className="stat-label">{label}</span>
        {Icon && <Icon className={cn("h-4 w-4 shrink-0", valueTone, "opacity-80")} />}
      </div>
      <div className={cn("mt-2 text-xl font-semibold tabular-nums", valueTone)}>
        {animateValue != null ? <AnimatedCount value={animateValue} /> : value}
      </div>
      {sub && <div className="mt-1 text-2xs text-fg-subtle">{sub}</div>}
    </div>
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
            y: reduceMotion ? 0 : 8,
            duration: reduceMotion ? 0 : 0.3,
            stagger: reduceMotion ? 0 : 0.05,
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
    <div ref={containerRef}>
      <Card className={cn("glass-card run-progress-panel", className)}>
        <div className="run-progress-layout">
          <div className="run-progress-ring-col">
            <ProgressRing
              pct={stats.pct}
              complete={stats.complete}
              total={stats.total}
              tone={
                stats.fail === 0
                  ? "success"
                  : stats.pass + stats.partial === 0
                    ? "danger"
                    : "warn"
              }
            />
            <div className="mt-3 text-center">
              <div className="flex flex-wrap items-center justify-center gap-2">
                <h2 className="text-sm font-medium text-fg">Run progress</h2>
                {live && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-2xs font-medium text-accent">
                    <Radio className="h-3 w-3 animate-pulse" aria-hidden />
                    Live
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="run-progress-stats-col">
            <div className="run-stat-grid">
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
              label="Pending"
              animateValue={stats.pending}
              sub="Pending"
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
        </div>
      </Card>
    </div>
  );
}
