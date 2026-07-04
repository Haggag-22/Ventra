"use client";

import { Button, Card } from "@/components/ui";
import { fmtNum } from "@/lib/format";
import type { RunMatrixStats } from "@/lib/run-matrix-stats";
import { caseHref, RUNS_NEW_HREF } from "@/lib/routes";
import type { RunStatus } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ListChecks,
  RotateCcw,
  XCircle,
} from "lucide-react";
import Link from "next/link";

export function RunCollectionSummary({
  stats,
  status,
  caseId,
  gapRows,
  className,
}: {
  stats: RunMatrixStats;
  status: RunStatus;
  caseId?: string | null;
  gapRows: { name: string; status: string; detail?: string }[];
  className?: string;
}) {
  const success = status === "completed" && stats.fail === 0;
  const failed = status === "failed" || stats.fail > 0;
  const cancelled = status === "cancelled";

  return (
    <Card className={cn("overflow-hidden", className)}>
      <div
        className={cn(
          "border-b px-4 py-3",
          success && "border-ok-green/30 bg-ok-green/10",
          failed && "border-bad-red/30 bg-bad-red/10",
          !success && !failed && "border-warn-amber/30 bg-warn-amber/10",
        )}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            {success ? (
              <CheckCircle2 className="h-5 w-5 text-ok-green" aria-hidden />
            ) : failed ? (
              <XCircle className="h-5 w-5 text-bad-red" aria-hidden />
            ) : (
              <AlertTriangle className="h-5 w-5 text-warn-amber" aria-hidden />
            )}
            <div>
              <h3 className="text-sm font-semibold text-fg">
                {success
                  ? "Collection complete"
                  : cancelled
                    ? "Collection cancelled"
                    : status === "failed"
                      ? "Collection failed"
                      : "Collection finished"}
              </h3>
              <p className="text-xs text-fg-subtle">
                {stats.pass + stats.partial} collected · {stats.fail} failed ·{" "}
                {fmtNum(stats.totalRecords)} records
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {caseId && (
              <Link href={caseHref(caseId)}>
                <Button variant="primary-dark" size="sm" icon={ExternalLink}>
                  Open case
                </Button>
              </Link>
            )}
            {stats.fail > 0 && (
              <Link href={RUNS_NEW_HREF}>
                <Button variant="secondary" size="sm" icon={RotateCcw}>
                  Re-run failed
                </Button>
              </Link>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-0 lg:grid-cols-2">
        <div className="border-b border-border p-4 lg:border-b-0 lg:border-r">
          <div className="mb-2 flex items-center gap-2 text-xs font-medium text-fg">
            <ListChecks className="h-4 w-4 text-ok-green" aria-hidden />
            Collected ({stats.collected.length})
          </div>
          {stats.collected.length === 0 ? (
            <p className="text-xs text-fg-subtle">No collectors finished successfully.</p>
          ) : (
            <ul className="max-h-56 space-y-1 overflow-auto text-xs">
              {stats.collected.map((row) => (
                <li
                  key={row.name}
                  className="flex items-center justify-between gap-2 rounded border border-ok-green/20 bg-ok-green/5 px-2 py-1.5"
                >
                  <span className="truncate font-medium text-fg">{row.name}</span>
                  <span className="mono shrink-0 text-fg-subtle">
                    {row.records > 0 ? `${fmtNum(row.records)} rec` : "—"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-medium text-fg">
            <AlertTriangle className="h-4 w-4 text-warn-amber" aria-hidden />
            Gaps / not collected ({gapRows.length})
          </div>
          {gapRows.length === 0 ? (
            <p className="text-xs text-fg-subtle">Full coverage — no gaps recorded.</p>
          ) : (
            <ul className="max-h-56 space-y-1 overflow-auto text-xs">
              {gapRows.map((row) => (
                <li
                  key={row.name}
                  className="rounded border border-warn-amber/25 bg-warn-amber/5 px-2 py-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-medium text-fg">{row.name}</span>
                    <span className="shrink-0 capitalize text-bad-red">{row.status}</span>
                  </div>
                  {row.detail && (
                    <p className="mt-0.5 truncate text-fg-subtle">{row.detail}</p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  );
}
