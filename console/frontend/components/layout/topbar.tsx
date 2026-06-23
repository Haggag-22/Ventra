"use client";

import { CloudPlatformLabel } from "@/components/cloud-provider-icon";
import { ExportElasticButton } from "@/components/export-elastic-button";
import { CASES_HREF } from "@/lib/routes";
import type { CaseSummary } from "@/lib/types";
import { fmtDateOnly } from "@/lib/format";
import { cn } from "@/lib/utils";
import { ChevronDown } from "lucide-react";
import Link from "next/link";

function MetaSegment({
  label,
  labelClassName,
  children,
}: {
  label: string;
  labelClassName?: string;
  children: React.ReactNode;
}) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn("text-2xs uppercase tracking-wide text-fg-subtle", labelClassName)}>
        {label}
      </span>
      {children}
    </span>
  );
}

function MetaDivider() {
  return <span className="h-3 w-px bg-border" aria-hidden />;
}

export function TopBar({
  caseId,
  summary,
}: {
  caseId: string;
  summary?: CaseSummary;
}) {
  const win = summary?.time_window;
  const windowLabel =
    win?.since || win?.until
      ? `${fmtDateOnly(win?.since)} → ${win?.until ? fmtDateOnly(win.until) : "now"}`
      : "Full available";

  const accountId = summary?.account_id ?? "—";

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border bg-raised px-4">
      <div className="flex min-w-0 items-center gap-3">
        <Link
          href={CASES_HREF}
          className="flex items-center gap-2 rounded-md border border-border bg-surface-2 px-2.5 py-1.5 hover:border-accent/40 transition-colors"
          title="Back to all cases"
        >
          <span className="text-2xs uppercase tracking-wide text-fg-subtle">Case</span>
          <span className="mono text-sm font-medium text-fg">{caseId}</span>
          <ChevronDown className="h-3.5 w-3.5 text-fg-subtle" />
        </Link>
      </div>

      <div className="flex min-w-0 items-center gap-3">
        {summary && (
          <div className="hidden shrink-0 items-center gap-3 text-xs md:flex">
            <MetaSegment label="Platform">
              <CloudPlatformLabel cloud={summary.cloud} />
            </MetaSegment>
            <MetaDivider />
            <MetaSegment label="Time range">
              <span className="font-bold text-fg">{windowLabel}</span>
            </MetaSegment>
            <MetaDivider />
            <MetaSegment label="Account ID">
              <span className="mono text-fg">{accountId}</span>
            </MetaSegment>
          </div>
        )}
        <ExportElasticButton caseId={caseId} />
      </div>
    </header>
  );
}
