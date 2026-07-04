"use client";

import { useCase } from "@/components/case-context";
import { Donut, SeverityBar } from "@/components/charts";
import { DashboardWidget } from "@/components/dashboard-widget";
import { PanelBody, PanelHeader } from "@/components/panel";
import { StatCard, KpiMetricCard, SegmentedProgress } from "@/components/stat";
import { LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import {
  aggregateManifestSources,
  catalogItems,
  missingCollectorIds,
  resolveCollectorCoverage,
} from "@/lib/collection-coverage";
import { type Cloud } from "@/lib/catalog";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { fmtNum } from "@/lib/format";
import { caseHref } from "@/lib/routes";
import { severityHex } from "@/lib/severity";
import type { Severity } from "@/lib/types";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  LayoutDashboard,
  ListChecks,
  Package,
  ScrollText,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

function ReadinessGauge({ pct }: { pct: number }) {
  const size = 100;
  const thickness = 10;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const len = (pct / 100) * c;
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="rgb(var(--border))"
            strokeWidth={thickness}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="rgb(var(--accent))"
            strokeWidth={thickness}
            strokeDasharray={`${len} ${c - len}`}
            strokeLinecap="round"
            className="glow-accent-soft"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums">{pct}%</span>
          <span className="stat-label">Ready</span>
        </div>
      </div>
      <SegmentedProgress value={pct} className="w-full max-w-[140px]" />
    </div>
  );
}

function coverageFromManifest(manifest: Record<string, unknown>): number {
  const cloud = (manifest.cloud ?? "aws") as Cloud;
  const bySource = aggregateManifestSources((manifest.sources as { name: string; status: string; record_count?: number; notes?: string }[]) ?? []);
  const gaps = (manifest.gaps as { name: string; reason: string; detail: string }[]) ?? [];
  const allItems = catalogItems(cloud);
  const collectedCount = allItems.filter((it) => {
    const r = resolveCollectorCoverage(it.id, bySource, gaps);
    return r.state === "collected" || r.state === "partial";
  }).length;
  return Math.round((collectedCount / Math.max(allItems.length, 1)) * 100);
}

export default function OverviewPage() {
  const { caseId } = useCase();

  const overviewQ = useQuery({
    queryKey: ["overview", caseId],
    queryFn: () => api.overview(caseId),
    retry: false,
  });

  const manifestQ = useQuery({
    queryKey: ["manifest", caseId],
    queryFn: () => api.manifest(caseId),
    enabled: overviewQ.isError,
  });

  const summaryQ = useQuery({
    queryKey: ["summary", caseId],
    queryFn: () => api.summary(caseId),
    enabled: overviewQ.isError,
  });

  const findingsQ = useQuery({
    queryKey: ["overview-findings", caseId],
    queryFn: () => api.facets(caseId, { source: ["findings"] }),
    enabled: overviewQ.isError,
  });

  const inventoryQ = useQuery({
    queryKey: ["inventory-summary", caseId],
    queryFn: () => api.inventorySummary(caseId),
    enabled: overviewQ.isError,
  });

  const eventsQ = useQuery({
    queryKey: ["overview-events", caseId],
    queryFn: () => api.events(caseId, { limit: 10, sort: "timestamp", order: "desc" }),
    enabled: overviewQ.isError,
  });

  const loading =
    overviewQ.isLoading ||
    (overviewQ.isError &&
      (manifestQ.isLoading || summaryQ.isLoading || findingsQ.isLoading || inventoryQ.isLoading));

  const data = useMemo(() => {
    if (overviewQ.data) {
      const manifest = overviewQ.data.manifest;
      const cloud = (manifest.cloud ?? overviewQ.data.summary.cloud ?? "aws") as Cloud;
      const bySource = aggregateManifestSources(
        (manifest.sources as { name: string; status: string; record_count?: number; notes?: string }[]) ?? [],
      );
      const gaps = (manifest.gaps as { name: string; reason: string; detail: string }[]) ?? [];
      return {
        summary: overviewQ.data.summary,
        severity: overviewQ.data.findings_by_severity,
        inventory: overviewQ.data.inventory,
        coveragePct: coverageFromManifest(manifest),
        gapLabels: missingCollectorIds(cloud, bySource, gaps),
        recent: overviewQ.data.recent_events,
      };
    }
    if (!manifestQ.data || !summaryQ.data) return null;
    const manifest = manifestQ.data;
    const cloud = (manifest.cloud ?? "aws") as Cloud;
    const bySource = aggregateManifestSources(manifest.sources ?? []);
    const gaps = manifest.gaps ?? [];
    const severity: Record<string, number> = {};
    for (const f of findingsQ.data?.event_severity ?? []) {
      severity[f.value] = f.count;
    }
    if (!Object.keys(severity).length) Object.assign(severity, summaryQ.data.by_severity);
    return {
      summary: summaryQ.data,
      severity,
      inventory: inventoryQ.data ?? { sources: [], categories: [], total_resources: 0 },
      coveragePct: coverageFromManifest(manifest),
      gapLabels: missingCollectorIds(cloud, bySource, gaps),
      recent: eventsQ.data?.events ?? [],
    };
  }, [overviewQ.data, manifestQ.data, summaryQ.data, findingsQ.data, inventoryQ.data, eventsQ.data]);

  if (loading || !data) return <LoadingPanel label="Loading overview…" />;

  const sevData = (["critical", "high", "medium", "low", "info"] as Severity[])
    .filter((s) => (data.severity[s] ?? 0) > 0)
    .map((s) => ({
      label: s,
      value: data.severity[s] ?? 0,
      color: severityHex(s),
    }));

  const invPreview = data.inventory.categories
    .flatMap((c) => c.items)
    .filter((i) => i.collected)
    .slice(0, 6);

  const totalFindings = Object.values(data.severity).reduce((a, b) => a + b, 0);
  const criticalHigh = (data.severity.critical ?? 0) + (data.severity.high ?? 0);

  return (
    <>
      <PanelHeader
        icon={LayoutDashboard}
        title="Overview"
        description="Investigation readiness and key signals for this case."
      />
      <PanelBody>
        {/* KPI hero row */}
        <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiMetricCard
            label="Collection readiness"
            value={`${data.coveragePct}%`}
            sub={`${data.gapLabels.length} gap${data.gapLabels.length === 1 ? "" : "s"} remaining`}
            icon={ListChecks}
            tone={data.coveragePct >= 75 ? "success" : data.coveragePct >= 50 ? "accent" : "high"}
            sparkline={[40, 55, 48, 62, 58, 70, data.coveragePct]}
          />
          <KpiMetricCard
            label="Total findings"
            value={fmtNum(totalFindings)}
            sub={criticalHigh > 0 ? `${fmtNum(criticalHigh)} critical/high` : "No critical/high"}
            icon={ShieldAlert}
            tone={criticalHigh > 0 ? "critical" : "default"}
            sparkline={[20, 35, 28, 45, 38, 52, Math.min(100, totalFindings > 0 ? 65 : 15)]}
          />
          <KpiMetricCard
            label="Resources"
            value={fmtNum(data.inventory.total_resources)}
            sub={`${data.inventory.sources.length} source${data.inventory.sources.length === 1 ? "" : "s"}`}
            icon={Package}
            sparkline={[30, 42, 50, 55, 60, 68, 72]}
          />
          <KpiMetricCard
            label="Collection gaps"
            value={fmtNum(data.gapLabels.length)}
            sub={data.gapLabels.length === 0 ? "Fully covered" : "Needs attention"}
            icon={AlertTriangle}
            tone={data.gapLabels.length > 0 ? "high" : "success"}
            sparkline={[60, 45, 38, 30, 22, 15, data.gapLabels.length > 0 ? 40 : 8]}
          />
        </div>

        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-4">
            <DashboardWidget
              title="Investigation readiness"
              icon={ListChecks}
              href={caseHref(caseId, "collection")}
            >
              <ReadinessGauge pct={data.coveragePct} />
              <p className="mt-2 text-center text-xs text-fg-subtle">
                {data.coveragePct}% of expected log sources collected
              </p>
            </DashboardWidget>
          </div>

          <div className="col-span-12 sm:col-span-6 lg:col-span-4">
            <DashboardWidget
              title="Findings by severity"
              icon={ShieldAlert}
              href={caseHref(caseId, "search")}
              emptyIcon={ShieldAlert}
              emptyTitle="No findings"
              emptyDescription="No severity-tagged findings in this case yet."
            >
              {sevData.length > 0 ? (
                <Donut
                  data={sevData}
                  size={100}
                  thickness={12}
                  centerValue={fmtNum(totalFindings)}
                  centerLabel="Findings"
                />
              ) : null}
            </DashboardWidget>
          </div>

          <div className="col-span-12 sm:col-span-6 lg:col-span-4">
            <DashboardWidget title="Risk severity" icon={ShieldAlert} href={caseHref(caseId, "search")}>
              <SeverityBar counts={data.severity} />
              <div className="mt-3 grid grid-cols-2 gap-2">
                {(["critical", "high", "medium"] as Severity[]).map((s) => (
                  <StatCard
                    key={s}
                    label={s}
                    value={fmtNum(data.severity[s] ?? 0)}
                    tone={s === "critical" ? "critical" : s === "high" ? "high" : "default"}
                  />
                ))}
              </div>
            </DashboardWidget>
          </div>

          <div className="col-span-12 lg:col-span-6">
            <DashboardWidget
              title="Resource inventory"
              icon={Package}
              href={caseHref(caseId, "resources")}
            >
              <p className="mb-3 text-sm text-fg-subtle">
                <span className="mono font-semibold text-fg">{fmtNum(data.inventory.total_resources)}</span>{" "}
                resources across {data.inventory.sources.length} source
                {data.inventory.sources.length === 1 ? "" : "s"}
              </p>
              <ul className="space-y-1.5 text-xs">
                {invPreview.map((item) => (
                  <li key={item.key} className="flex justify-between gap-2 border-b border-border/50 py-1">
                    <span className="truncate text-fg">{item.label}</span>
                    <span className="mono shrink-0 text-fg-subtle">
                      {item.count != null ? fmtNum(item.count) : "—"}
                    </span>
                  </li>
                ))}
              </ul>
            </DashboardWidget>
          </div>

          <div className="col-span-12 lg:col-span-6">
            <DashboardWidget
              title="Collection gaps"
              icon={AlertTriangle}
              href={caseHref(caseId, "collection")}
              emptyIcon={ListChecks}
              emptyTitle="No gaps"
              emptyDescription="All implemented collectors have data or known posture."
            >
              {data.gapLabels.length > 0 ? (
                <ul className="max-h-48 space-y-2 overflow-auto text-xs">
                  {data.gapLabels.slice(0, 8).map((name) => (
                    <li
                      key={name}
                      className="rounded border border-warn-amber/30 bg-warn-amber/5 px-2 py-1.5 text-fg"
                    >
                      {displayArtifactLabel(name)}
                    </li>
                  ))}
                </ul>
              ) : null}
            </DashboardWidget>
          </div>

          <div className="col-span-12">
            <DashboardWidget
              title="Recent activity"
              icon={ScrollText}
              href={caseHref(caseId, "cloudtrail")}
            >
              {data.recent.length === 0 ? (
                <p className="py-4 text-center text-sm text-fg-subtle">No recent events.</p>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-border bg-surface-2/40">
                          <th className="table-header-cell !px-0 !pr-3">Time</th>
                          <th className="table-header-cell !px-0 !pr-3">Action</th>
                          <th className="table-header-cell !px-0 !pr-3">Principal</th>
                          <th className="table-header-cell !px-0">Source</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.recent.map((ev, i) => (
                          <tr key={`${ev.timestamp}-${i}`} className="border-b border-border/40">
                            <td className="table-cell-muted mono !px-0 !pr-3">{ev.timestamp?.slice(0, 19)}</td>
                            <td className="table-cell !px-0 !pr-3">{ev.event_action || "—"}</td>
                            <td className="table-cell-muted mono !px-0 !pr-3">{ev.user_name || "—"}</td>
                            <td className="table-cell-muted !px-0">{ev.ventra_source || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <Link
                    href={caseHref(caseId, "cloudtrail")}
                    className="mt-3 inline-block text-xs text-accent hover:underline"
                  >
                    View all events
                  </Link>
                </>
              )}
            </DashboardWidget>
          </div>
        </div>
      </PanelBody>
    </>
  );
}
