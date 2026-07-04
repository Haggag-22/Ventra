"use client";

import { Breadcrumbs } from "@/components/layout/breadcrumbs";
import { CloudPlatformLabel } from "@/components/cloud-provider-icon";
import { ExportElasticButton } from "@/components/export-elastic-button";
import { useUI } from "@/app/providers";
import { CASES_HREF, breadcrumbsFromPath } from "@/lib/routes";
import type { CaseSummary } from "@/lib/types";
import { fmtDateOnly } from "@/lib/format";
import { cn } from "@/lib/utils";
import { ChevronDown, Moon, Sun, SunMoon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

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

function ThemeToggle() {
  const { theme, setTheme } = useUI();
  const cycle = () => {
    const next =
      theme === "light" ? "contrast" : theme === "contrast" ? "dark" : "light";
    setTheme(next);
  };
  const Icon =
    theme === "light" ? Sun : theme === "contrast" ? SunMoon : Moon;
  return (
    <button
      type="button"
      onClick={cycle}
      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border bg-surface text-fg-subtle transition-colors hover:border-accent/40 hover:bg-surface-2 hover:text-fg"
      title={`Theme: ${theme}`}
      aria-label={`Switch theme (current: ${theme})`}
    >
      <Icon className="h-4 w-4" />
    </button>
  );
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
  const pathname = usePathname();
  const crumbs = breadcrumbsFromPath(pathname, caseId);
  const win = summary?.time_window;
  const windowLabel =
    win?.since || win?.until
      ? `${fmtDateOnly(win?.since)} → ${win?.until ? fmtDateOnly(win.until) : "now"}`
      : "Full available";

  const accountId = summary?.account_id ?? "—";

  return (
    <header className="flex h-[3.75rem] shrink-0 items-center justify-between gap-6 border-b border-border/80 bg-raised px-6">
      <div className="flex min-w-0 items-center gap-3">
        {variant === "case" && caseId ? (
          <Link
            href={CASES_HREF}
            className="flex items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5 transition-colors hover:border-accent/45 hover:bg-surface-2"
            title="Back to all cases"
          >
            <span className="text-2xs uppercase tracking-wide text-fg-subtle">Case</span>
            <span className="mono text-sm font-medium text-fg">{caseId}</span>
            <ChevronDown className="h-3.5 w-3.5 text-fg-subtle" />
          </Link>
        ) : (
          <Breadcrumbs items={crumbs} />
        )}
      </div>

      <div className="flex min-w-0 items-center gap-3">
        {variant === "case" && summary && (
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
        {variant === "case" && caseId && <ExportElasticButton caseId={caseId} />}
        <ThemeToggle />
      </div>
    </header>
  );
}
