"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Button, Card, LoadingPanel } from "@/components/ui";
import { clearKitHandoff, getKitHandoff } from "@/lib/acquire-handoff";
import { api } from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { CLOUD_IMPLEMENTED, type Cloud } from "@/lib/catalog";
import {
  ACQUIRABLE_COVERAGE,
  aggregateManifestSources,
  catalogItems,
  IMPLEMENTED_LOG_COLLECTORS,
  missingCollectorIds,
  resolveCollectorCoverage,
  type CoverageState,
} from "@/lib/collection-coverage";
import { deploymentProfileLabel } from "@/lib/deployment-profiles";
import { fmtNum } from "@/lib/format";
import { acquireHref, CASES_HREF } from "@/lib/routes";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckSquare,
  Clock,
  Download,
  ListChecks,
  MinusSquare,
  Plus,
  Square,
  Upload,
  XSquare,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

const STATE_META: Record<
  CoverageState,
  { label: string; icon: typeof Square; tone: string; collected: boolean }
> = {
  collected: { label: "Collected", icon: CheckSquare, tone: "text-ok-green", collected: true },
  partial: { label: "Partial", icon: AlertTriangle, tone: "text-warn-amber", collected: true },
  empty: { label: "No records", icon: MinusSquare, tone: "text-warn-amber", collected: false },
  not_enabled: { label: "Not enabled", icon: XSquare, tone: "text-bad-red", collected: false },
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
  const pendingKit = useMemo(() => getKitHandoff(caseId), [caseId]);
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

  const missingIds = missingCollectorIds(cloud, bySource, gaps);
  const coveragePct = Math.round((collectedCount / Math.max(allItems.length, 1)) * 100);

  return (
    <>
      <PanelHeader
        icon={ListChecks}
        title="Logs Coverage"
        panel="collection"
        actions={
          <div className="flex items-center gap-3">
            <span className="text-xs text-fg-subtle">
              <span className="text-ok-green font-medium">{collectedCount}</span> / {allItems.length}{" "}
              log sources
            </span>
            {missingIds.length > 0 && CLOUD_IMPLEMENTED[cloud] && (
              <Link href={acquireHref({ caseId, cloud, collectors: missingIds })}>
                <Button variant="secondary" icon={Download} className="h-8 text-xs">
                  Build kit ({missingIds.length} missing)
                </Button>
              </Link>
            )}
          </div>
        }
      />
      <PanelBody className="cloudtrail-view space-y-5">
        {pendingKit && (
          <div className="rounded-lg border border-accent/30 bg-accent/5 px-4 py-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="space-y-1 text-xs text-fg">
                <p className="flex items-center gap-2 font-medium">
                  <Clock className="h-4 w-4 text-accent" />
                  Kit sent — awaiting client upload
                </p>
                <p className="text-fg-subtle">
                  Built{" "}
                  <span className="mono">{new Date(pendingKit.builtAt).toLocaleString()}</span> ·{" "}
                  {deploymentProfileLabel(pendingKit.deploymentProfile)} ·{" "}
                  {pendingKit.collectors.length} expected artifact
                  {pendingKit.collectors.length === 1 ? "" : "s"}
                </p>
                <ul className="mt-2 max-h-20 space-y-0.5 overflow-auto mono text-2xs text-fg-subtle">
                  {pendingKit.collectors.map((c) => (
                    <li key={c}>{displayArtifactLabel(c)}</li>
                  ))}
                </ul>
              </div>
              <div className="flex flex-wrap gap-2">
                <Link href={`${CASES_HREF}?import_case=${encodeURIComponent(caseId)}`}>
                  <Button variant="primary-dark" icon={Upload} className="h-8 text-xs">
                    Import evidence
                  </Button>
                </Link>
                <Button
                  variant="ghost"
                  className="h-8 text-xs"
                  onClick={() => clearKitHandoff(caseId)}
                >
                  Dismiss
                </Button>
              </div>
            </div>
          </div>
        )}

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
            <Legend icon={XSquare} tone="text-bad-red" label="Not enabled" />
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
                    const canAcquire =
                      CLOUD_IMPLEMENTED[cloud] &&
                      IMPLEMENTED_LOG_COLLECTORS.has(it.id) &&
                      ACQUIRABLE_COVERAGE.has(r.state);

                    return (
                      <tr key={it.id}>
                        <td className="font-medium text-fg">
                          <div className="flex items-center justify-between gap-2">
                            <span>{it.label}</span>
                            {canAcquire && (
                              <Link
                                href={acquireHref({ caseId, cloud, collectors: [it.id] })}
                                className="inline-flex items-center gap-1 text-2xs text-accent hover:underline"
                                title={`Add ${it.id} to collection kit`}
                              >
                                <Plus className="h-3 w-3" />
                                Acquire
                              </Link>
                            )}
                          </div>
                        </td>
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
