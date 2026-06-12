"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Card, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { CLOUD_IMPLEMENTED, type Cloud } from "@/lib/catalog";
import {
  aggregateManifestSources,
  catalogItems,
  IMPLEMENTED_LOG_COLLECTORS,
  resolveCollectorCoverage,
  type CoverageState,
} from "@/lib/collection-coverage";
import { fmtNum } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckSquare,
  ListChecks,
  MinusSquare,
  Square,
  XSquare,
} from "lucide-react";

const STATE_META: Record<
  CoverageState,
  { label: string; icon: typeof Square; tone: string; collected: boolean }
> = {
  collected: { label: "Collected", icon: CheckSquare, tone: "text-ok-green", collected: true },
  partial: { label: "Partial", icon: AlertTriangle, tone: "text-warn-amber", collected: true },
  empty: { label: "No records", icon: MinusSquare, tone: "text-warn-amber", collected: false },
  not_enabled: { label: "Not enabled", icon: Square, tone: "text-warn-amber", collected: false },
  denied: { label: "Access denied", icon: XSquare, tone: "text-bad-red", collected: false },
  not_run: { label: "Not run", icon: Square, tone: "text-fg-subtle", collected: false },
  planned: { label: "Detected only", icon: Square, tone: "text-fg-subtle", collected: false },
};

function displayState(id: string, state: CoverageState): CoverageState {
  if ((state === "not_run" || state === "planned") && !IMPLEMENTED_LOG_COLLECTORS.has(id)) {
    return "planned";
  }
  return state;
}

function rowDetail(
  state: CoverageState,
  display: CoverageState,
  detail: string,
  gaps: { name: string; detail: string }[],
): string {
  // "Detected only" rows carry the posture note (enabled? where does it ship?) — the
  // analyst's pointer for manual collection. Show it.
  if (display === "planned") {
    return detail || "No Ventra collector for this source yet.";
  }
  if (state === "partial" && gaps.length) {
    return gaps.map((g) => g.detail).join(" ");
  }
  if (state !== "collected" && detail) return detail;
  return "";
}

export default function CollectionPage() {
  const { caseId } = useCase();
  const manifestQ = useQuery({ queryKey: ["manifest", caseId], queryFn: () => api.manifest(caseId) });
  const summaryQ = useQuery({ queryKey: ["summary", caseId], queryFn: () => api.summary(caseId) });

  if (manifestQ.isLoading || summaryQ.isLoading || !manifestQ.data || !summaryQ.data)
    return <LoadingPanel label="Loading logs coverage…" />;

  const manifest = manifestQ.data;
  const cloud = (manifest.cloud ?? "aws") as Cloud;
  const bySource = aggregateManifestSources(manifest.sources ?? []);
  const gaps: { name: string; reason: string; detail: string }[] = manifest.gaps ?? [];

  const resolve = (id: string) => resolveCollectorCoverage(id, bySource, gaps);

  const allItems = catalogItems(cloud);
  const resolved = allItems.map((it) => ({ it, r: resolve(it.id) }));

  const collectedCount = resolved.filter(
    (x) => x.r.state === "collected" || x.r.state === "partial",
  ).length;

  const coveragePct = Math.round((collectedCount / Math.max(allItems.length, 1)) * 100);

  return (
    <>
      <PanelHeader
        icon={ListChecks}
        title="Logs Coverage"
        panel="collection"
        actions={
          <span className="text-xs text-fg-subtle">
            <span className="text-ok-green font-medium">{collectedCount}</span> / {allItems.length}{" "}
            log sources
          </span>
        }
      />
      <PanelBody className="cloudtrail-view space-y-5">
        {!CLOUD_IMPLEMENTED[cloud] && (
          <div className="rounded-lg border border-warn-amber/30 bg-warn-amber/10 px-4 py-3 text-xs text-warn-amber">
            {cloud.toUpperCase()} collectors are scaffolded but not yet implemented — these
            artifacts are shown as planned coverage.
          </div>
        )}

        <Card className="p-4">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-fg-subtle">
            <span className="stat-label">Logs coverage</span>
            <span className="mono">{coveragePct}%</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2">
            <div
              className="h-full rounded-full bg-ok-green"
              style={{ width: `${coveragePct}%` }}
            />
          </div>
          <div className="mt-3 flex flex-wrap gap-3 text-2xs text-fg-subtle">
            <Legend icon={CheckSquare} tone="text-ok-green" label="Collected" />
            <Legend icon={AlertTriangle} tone="text-warn-amber" label="Partial" />
            <Legend icon={MinusSquare} tone="text-warn-amber" label="No records" />
            <Legend icon={Square} tone="text-warn-amber" label="Not enabled" />
            <Legend icon={XSquare} tone="text-bad-red" label="Access denied" />
            <Legend icon={Square} tone="text-fg-subtle" label="Detected only (manual pull)" />
          </div>
        </Card>

        <div>
          <h2 className="mb-2 text-sm font-semibold text-fg">Logs Checked</h2>
          <div className="ct-panel">
            <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
              <table className="ct-table ct-table-no-row-click w-full border-collapse text-left">
                <thead className="sticky top-0 z-10">
                  <tr>
                    <th className="w-[38%]">Log source</th>
                    <th className="w-[14%]">Status</th>
                    <th className="w-[10%]">Records</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {resolved.map(({ it, r }) => {
                    const display = displayState(it.id, r.state);
                    const meta = STATE_META[display];
                    const Icon = meta.icon;
                    const notes = rowDetail(r.state, display, r.detail, r.gaps);
                    const records =
                      (r.state === "collected" || r.state === "partial") && r.records > 0
                        ? fmtNum(r.records)
                        : "—";

                    return (
                      <tr key={it.id}>
                        <td className="font-medium text-fg">{it.label}</td>
                        <td>
                          <span className={cn("inline-flex items-center gap-1.5", meta.tone)}>
                            <Icon className="h-4 w-4 shrink-0" />
                            {meta.label}
                          </span>
                        </td>
                        <td className="mono text-fg-subtle">{records}</td>
                        <td className="text-fg-subtle">{notes || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </PanelBody>
    </>
  );
}

function Legend({ icon: Icon, tone, label }: { icon: typeof Square; tone: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <Icon className={cn("h-3.5 w-3.5", tone)} />
      {label}
    </span>
  );
}
