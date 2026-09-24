"use client";

import { CloudPlatformLabel } from "@/components/cloud-provider-icon";
import { ExportElasticButton } from "@/components/export-elastic-button";
import { ThemeToggle } from "@/components/layout/theme-toggle";
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
    <span className="inline-flex items-center gap-2">
      <span className={cn("text-xs font-medium uppercase tracking-wide text-fg-subtle", labelClassName)}>
        {label}
      </span>
      {children}
    </span>
  );
}

function MetaDivider() {
  return <span className="h-4 w-px bg-border" aria-hidden />;
}

export function TopBar({
  caseId,
  summary,
  variant = "case",
}: {
  caseId?: string;
  summary?: CaseSummary;
  variant?: "case" | "global";
}) {
  const win = summary?.time_window;
  const windowLabel =
    win?.since || win?.until
      ? `${fmtDateOnly(win?.since)} → ${win?.until ? fmtDateOnly(win.until) : "now"}`
      : "Full available";

  const accountId = summary?.account_id ?? "—";

  if (variant === "global") {
    return null;
  }

  return (
    <header className="flex min-h-[4.5rem] shrink-0 items-center justify-between gap-6 bg-transparent px-6 pb-3 pt-4">
      <div className="flex min-w-0 items-center gap-3">
        {caseId ? (
          <Link
            href={CASES_HREF}
            className="flex items-center gap-2 rounded-md border border-accent-cta/45 bg-accent-cta/10 px-3 py-2 transition-colors hover:border-accent-cta/60 hover:bg-accent-cta/15"
            title="Back to all cases"
          >
            <span className="text-2xs uppercase tracking-wide text-fg-subtle">Case</span>
            <span className="mono text-sm font-medium text-fg">{caseId}</span>
            <ChevronDown className="h-3.5 w-3.5 text-fg-subtle" />
          </Link>
        ) : null}
      </div>

      <div className="flex min-w-0 items-center gap-3">
        {summary && (
          <div className="hidden shrink-0 items-center gap-4 text-sm md:flex">
            <MetaSegment label="Platform">
              <CloudPlatformLabel cloud={summary.cloud} className="text-sm font-semibold" />
            </MetaSegment>
            <MetaDivider />
            <MetaSegment label="Time range">
              <span className="text-sm font-semibold text-fg">{windowLabel}</span>
            </MetaSegment>
            <MetaDivider />
            <MetaSegment label="Account ID">
              <span className="mono text-sm font-semibold text-fg">{accountId}</span>
            </MetaSegment>
          </div>
        )}
        {caseId && <ExportElasticButton caseId={caseId} />}
        <ThemeToggle />
      </div>
    </header>
  );
}
