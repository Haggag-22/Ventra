"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { fmtNum } from "@/lib/format";
import type { CasePlatform } from "@/lib/catalog";
import type { CaseSummary, Integrity } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  Clock,
  Fingerprint,
  MapPin,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
} from "lucide-react";

const SEAL: Record<
  Integrity,
  { label: string; cls: string; icon: typeof ShieldCheck }
> = {
  green: {
    label: "Sealed · verified",
    cls: "border-ok-green/40 bg-ok-green/10 text-ok-green",
    icon: ShieldCheck,
  },
  amber: {
    label: "Sealed · advisory",
    cls: "border-warn-amber/40 bg-warn-amber/10 text-warn-amber",
    icon: ShieldAlert,
  },
  red: {
    label: "Integrity failed",
    cls: "border-bad-red/40 bg-bad-red/10 text-bad-red",
    icon: ShieldX,
  },
  unknown: {
    label: "Unsealed",
    cls: "border-border bg-surface-2 text-fg-subtle",
    icon: ShieldQuestion,
  },
};

function fmtDate(iso?: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function HeaderStat({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  tone?: "default" | "accent" | "warn" | "bad";
}) {
  return (
    <div className="rounded-md border border-border bg-bg/45 px-3 py-2.5">
      <div className="stat-label">{label}</div>
      <div
        className={cn(
          "mt-1 text-xl font-semibold tabular-nums",
          tone === "accent" && "text-accent",
          tone === "warn" && "text-warn-amber",
          tone === "bad" && "text-bad-red",
        )}
      >
        {value}
      </div>
    </div>
  );
}

export function CaseOverviewHeader({
  summary,
  coveragePct,
}: {
  summary: CaseSummary;
  coveragePct: number;
}) {
  const integrity = (summary.integrity ?? "unknown") as Integrity;
  const seal = SEAL[integrity] ?? SEAL.unknown;
  const SealIcon = seal.icon;

  const alias = summary.account_alias?.trim();
  const primary = alias || summary.account_id || "Case";
  const secondary = alias ? summary.account_id : summary.case_id;

  const start = fmtDate(summary.started_at);
  const end = fmtDate(summary.completed_at);
  const window = start && end ? (start === end ? start : `${start} → ${end}`) : start || end;

  const totals = summary.totals;

  return (
    <section className="mb-6 overflow-hidden rounded-xl border border-border bg-surface">
      <div className="flex flex-col gap-5 p-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-2xs font-semibold uppercase tracking-wide",
                seal.cls,
              )}
            >
              <SealIcon className="h-3.5 w-3.5" />
              {seal.label}
            </span>
            {summary.signature_method && (
              <span className="inline-flex items-center gap-1 text-2xs text-fg-faint">
                <Fingerprint className="h-3 w-3" />
                <span className="mono">{summary.signature_method}</span>
              </span>
            )}
          </div>

          <div className="mt-3 flex items-center gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-border bg-bg">
              <CloudProviderIcon cloud={summary.cloud as CasePlatform} />
            </span>
            <div className="min-w-0">
              <h1 className="page-title min-w-0">
                <span className="min-w-0 truncate">{primary}</span>
              </h1>
              {secondary && (
                <p className="mono truncate text-xs text-fg-subtle" title={secondary}>
                  {secondary}
                </p>
              )}
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-subtle">
            {window && (
              <span className="inline-flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-fg-faint" />
                Collected {window}
              </span>
            )}
            {summary.regions?.length > 0 && (
              <span className="inline-flex items-center gap-1.5">
                <MapPin className="h-3.5 w-3.5 text-fg-faint" />
                {summary.regions.length} region{summary.regions.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
        </div>

        <div className="grid shrink-0 grid-cols-2 gap-2 sm:grid-cols-4">
          <HeaderStat
            label="Readiness"
            value={`${coveragePct}%`}
            tone={coveragePct >= 75 ? "accent" : coveragePct >= 50 ? "default" : "warn"}
          />
          <HeaderStat label="Events" value={fmtNum(totals?.events ?? 0)} />
          <HeaderStat
            label="Sensitive"
            value={fmtNum(totals?.sensitive_actions ?? 0)}
            tone={(totals?.sensitive_actions ?? 0) > 0 ? "warn" : "default"}
          />
          <HeaderStat
            label="Failures"
            value={fmtNum(totals?.failures ?? 0)}
            tone={(totals?.failures ?? 0) > 0 ? "bad" : "default"}
          />
        </div>
      </div>
    </section>
  );
}
