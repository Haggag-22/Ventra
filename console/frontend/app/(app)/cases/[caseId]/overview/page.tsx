"use client";

import { CaseOverviewHeader } from "@/components/case-overview-header";
import { useCase } from "@/components/case-context";
import { Donut, RadarChart, SeverityBar } from "@/components/charts";
import { DashboardWidget } from "@/components/dashboard-widget";
import { KpiMetricCard, SegmentedProgress } from "@/components/stat";
import { LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import {
  aggregateManifestSources,
  catalogItems,
  familyCoverage,
  missingCollectorIds,
  resolveCollectorCoverage,
} from "@/lib/collection-coverage";
import { type Cloud } from "@/lib/catalog";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { fmtNum } from "@/lib/format";
import { caseHref } from "@/lib/routes";
import { severityHex } from "@/lib/severity";
import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  LayoutDashboard,
  ListChecks,
  Package,
  Radar,
  ScrollText,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

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

/** Compact HH:MM:SS from an ISO timestamp, falling back to the raw head. */
function eventTime(iso?: string): string {
  if (!iso) return "—";
  const t = iso.includes("T") ? iso.slice(11, 19) : iso.slice(0, 19);
  return t || "—";
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
        families: familyCoverage(cloud, bySource, gaps),
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
      families: familyCoverage(cloud, bySource, gaps),
      recent: eventsQ.data?.events ?? [],
    };
  }, [overviewQ.data, manifestQ.data, summaryQ.data, findingsQ.data, inventoryQ.data, eventsQ.data]);

  if (loading || !data) return <LoadingPanel label="Loading overview…" />;

  const sevData = (["critical", "high", "medium", "low", "info"] as Severity[])
    .filter((s) => (data.severity[s] ?? 0) > 0)
    .map((s) => ({ label: s, value: data.severity[s] ?? 0, color: severityHex(s) }));

  const invPreview = data.inventory.categories
    .flatMap((c) => c.items)
    .filter((i) => i.collected)
    .slice(0, 6);

  const totalFindings = Object.values(data.severity).reduce((a, b) => a + b, 0);
  const criticalHigh = (data.severity.critical ?? 0) + (data.severity.high ?? 0);
  const radarAxes = data.families.map((f) => ({ label: f.short, value: f.pct }));

  return (
    <div className="px-6 py-6">
      <CaseOverviewHeader summary={data.summary} coveragePct={data.coveragePct} />

      {/* KPI row — real values, no fabricated trends */}
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiMetricCard
          label="Collection readiness"
          value={`${data.coveragePct}%`}
          tone={data.coveragePct >= 75 ? "success" : data.coveragePct >= 50 ? "accent" : "high"}
          icon={ListChecks}
          sub={
            <div className="mt-2 space-y-1.5">
              <SegmentedProgress value={data.coveragePct} className="max-w-[130px]" />
              <span className="block">
                {data.gapLabels.length} gap{data.gapLabels.length === 1 ? "" : "s"} remaining
              </span>
            </div>
          }
        />
        <KpiMetricCard
          label="Total findings"
          value={fmtNum(totalFindings)}
          tone={criticalHigh > 0 ? "critical" : "default"}
          icon={ShieldAlert}
          sub={
            totalFindings > 0 ? (
              <div className="mt-2 space-y-1.5">
                <SeverityBar counts={data.severity} />
                <span className="block">
                  {criticalHigh > 0 ? `${fmtNum(criticalHigh)} critical/high` : "No critical/high"}
                </span>
              </div>
            ) : (
              "No findings"
            )
          }
        />
        <KpiMetricCard
          label="Resources"
          value={fmtNum(data.inventory.total_resources)}
          icon={Package}
          sub={`${data.inventory.sources.length} source${data.inventory.sources.length === 1 ? "" : "s"}`}
        />
        <KpiMetricCard
          label="Collection gaps"
          value={fmtNum(data.gapLabels.length)}
          tone={data.gapLabels.length > 0 ? "high" : "success"}
          icon={AlertTriangle}
          sub={data.gapLabels.length === 0 ? "Fully covered — no gaps" : "Missing telemetry is evidence"}
        />
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Coverage radar — Ventra's "gaps as evidence" at a glance */}
        <div className="col-span-12 lg:col-span-5">
          <DashboardWidget
            title="Coverage by source"
            icon={Radar}
            href={caseHref(caseId, "collection")}
          >
            <div className="flex flex-col items-center gap-5 sm:flex-row">
              {radarAxes.length >= 3 && (
                <div className="shrink-0">
                  <RadarChart axes={radarAxes} size={196} />
                </div>
              )}
              <ul className="w-full space-y-2">
                {data.families.map((f) => (
                  <li key={f.family} className="flex items-center justify-between gap-2 text-xs">
                    <span className="truncate text-fg-subtle">{f.label}</span>
                    <span className="flex shrink-0 items-center gap-2">
                      <span
                        className={cn(
                          "mono font-medium",
                          f.pct >= 75 ? "text-ok-green" : f.pct >= 34 ? "text-warn-amber" : "text-fg-subtle",
                        )}
                      >
                        {f.pct}%
                      </span>
                      <span className="mono text-2xs text-fg-faint">
                        {f.collected}/{f.total}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </DashboardWidget>
        </div>

        {/* Findings — single consolidated severity view */}
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
              <div className="space-y-4">
                <Donut
                  data={sevData}
                  size={104}
                  thickness={12}
                  centerValue={fmtNum(totalFindings)}
                  centerLabel="Findings"
                />
                <SeverityBar counts={data.severity} />
              </div>
            ) : null}
          </DashboardWidget>
        </div>

        {/* Collection gaps */}
        <div className="col-span-12 sm:col-span-6 lg:col-span-3">
          <DashboardWidget
            title="Collection gaps"
            icon={AlertTriangle}
            href={caseHref(caseId, "collection")}
            emptyIcon={ListChecks}
            emptyTitle="No gaps"
            emptyDescription="All implemented collectors have data or known posture."
          >
            {data.gapLabels.length > 0 ? (
              <ul className="max-h-56 space-y-2 overflow-auto text-xs">
                {data.gapLabels.slice(0, 10).map((name) => (
                  <li
                    key={name}
                    className="rounded-md border border-warn-amber/30 bg-warn-amber/5 px-2.5 py-1.5 text-fg"
                  >
                    {displayArtifactLabel(name)}
                  </li>
                ))}
              </ul>
            ) : null}
          </DashboardWidget>
        </div>

        {/* Resource inventory */}
        <div className="col-span-12 lg:col-span-5">
          <DashboardWidget title="Resource inventory" icon={Package} href={caseHref(caseId, "resources")}>
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

        {/* Recent activity — timeline feed */}
        <div className="col-span-12 lg:col-span-7">
          <DashboardWidget title="Recent activity" icon={ScrollText} href={caseHref(caseId, "cloudtrail")}>
            {data.recent.length === 0 ? (
              <p className="py-4 text-center text-sm text-fg-subtle">No recent events.</p>
            ) : (
              <>
                <ul className="divide-y divide-border/40">
                  {data.recent.map((ev, i) => {
                    const meta = [ev.user_name || ev.user_arn, ev.source_ip, ev.cloud_service || ev.event_provider]
                      .filter(Boolean)
                      .join(" · ");
                    const failed = ev.event_outcome === "failure";
                    return (
                      <li key={`${ev.timestamp}-${i}`} className="flex items-start gap-3 py-2">
                        <time className="mono w-16 shrink-0 pt-0.5 text-2xs text-fg-faint" title={ev.timestamp}>
                          {eventTime(ev.timestamp)}
                        </time>
                        <span
                          className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{ background: severityHex(ev.event_severity || "info") }}
                          aria-hidden
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm text-fg">
                            {ev.event_action || "—"}
                            {failed && <span className="ml-2 text-2xs font-medium text-bad-red">failed</span>}
                          </p>
                          {meta && <p className="mono truncate text-2xs text-fg-subtle">{meta}</p>}
                        </div>
                      </li>
                    );
                  })}
                </ul>
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
    </div>
  );
}
