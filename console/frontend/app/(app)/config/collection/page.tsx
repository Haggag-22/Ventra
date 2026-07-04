"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Badge, Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { KpiMetricCard, SegmentedProgress } from "@/components/stat";
import { listConnections, listRuns } from "@/lib/api";
import { CASE_PLATFORM_LABELS, type CasePlatform } from "@/lib/catalog";
import {
  ACQUIRE_HREF,
  caseHref,
  runHref,
  RUNS_NEW_HREF,
} from "@/lib/routes";
import type { RunMeta, RunStatus } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  ExternalLink,
  Eye,
  Play,
  Plus,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

type StatusFilter = "all" | "running" | "completed" | "failed" | "cancelled";

const FILTERS: { id: StatusFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "running", label: "Running" },
  { id: "completed", label: "Completed" },
  { id: "failed", label: "Failed" },
  { id: "cancelled", label: "Cancelled" },
];

function statusTone(status: RunStatus): string {
  if (status === "completed") return "text-ok-green bg-ok-green/10 border-ok-green/30";
  if (status === "failed") return "text-bad-red bg-bad-red/10 border-bad-red/30";
  if (status === "cancelled") return "text-fg-subtle bg-surface-2 border-border";
  if (status === "running" || status === "pending")
    return "text-accent bg-accent/10 border-accent/30";
  return "text-fg-subtle bg-surface-2 border-border";
}

function fmtDuration(meta: RunMeta): string {
  if (meta.duration_ms != null) {
    const ms = meta.duration_ms;
    if (ms < 1000) return `${ms}ms`;
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    return `${Math.floor(s / 60)}m ${s % 60}s`;
  }
  if (meta.finished_at && meta.created_at) {
    const ms = Date.parse(meta.finished_at) - Date.parse(meta.created_at);
    if (Number.isFinite(ms) && ms > 0) return fmtDuration({ duration_ms: ms } as RunMeta);
  }
  return "—";
}

function runProgress(meta: RunMeta): { complete: number; total: number } {
  const complete = meta.progress?.complete ?? meta.collectors_complete ?? 0;
  const total = meta.progress?.total ?? meta.collectors_total ?? 0;
  return { complete, total };
}

function matchesFilter(status: RunStatus, filter: StatusFilter): boolean {
  if (filter === "all") return true;
  if (filter === "running") return status === "running" || status === "pending";
  return status === filter;
}

export default function CollectionPage() {
  const router = useRouter();
  const [filter, setFilter] = useState<StatusFilter>("all");

  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: listRuns,
    retry: false,
    refetchInterval: (q) => {
      const rows = q.state.data?.runs ?? [];
      const active = rows.some((r) => r.status === "running" || r.status === "pending");
      return active ? 2500 : false;
    },
  });

  const connections = useQuery({
    queryKey: ["config", "connections"],
    queryFn: listConnections,
    staleTime: 60_000,
  });

  const connectionNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of connections.data?.connections ?? []) {
      map.set(c.id, c.name);
    }
    return map;
  }, [connections.data]);

  const all = runs.data?.runs ?? [];
  const countFor = (f: StatusFilter) =>
    f === "all" ? all.length : all.filter((r) => matchesFilter(r.status, f)).length;
  const visible = all.filter((r) => matchesFilter(r.status, filter));

  const runningCount = countFor("running");
  const completedCount = countFor("completed");
  const failedCount = countFor("failed");
  const avgProgress =
    all.length > 0
      ? Math.round(
          all.reduce((sum, r) => {
            const { complete, total } = runProgress(r);
            return sum + (total > 0 ? (complete / total) * 100 : 0);
          }, 0) / all.length,
        )
      : 0;

  return (
    <div className="px-6 py-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="page-title">
            <Activity className="h-5 w-5 text-accent" />
            Collection
          </h1>
          <p className="page-subtitle">
            Monitor ongoing and completed evidence collection jobs across your providers.
          </p>
        </div>
        <Link href={RUNS_NEW_HREF}>
          <Button variant="primary-dark" icon={Plus} className="bg-accent text-accent-fg hover:bg-accent/90">
            Run collection
          </Button>
        </Link>
      </div>

      {!runs.isLoading && !runs.isError && all.length > 0 && (
        <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiMetricCard
            label="Total runs"
            value={all.length}
            sub={`${runningCount} active`}
            icon={Activity}
            tone="accent"
            sparkline={[25, 40, 35, 50, 45, 60, 55]}
          />
          <KpiMetricCard
            label="Completed"
            value={completedCount}
            sub={all.length > 0 ? `${Math.round((completedCount / all.length) * 100)}% success rate` : "—"}
            tone="success"
            sparkline={[20, 30, 45, 55, 60, 70, 75]}
          />
          <KpiMetricCard
            label="Failed"
            value={failedCount}
            sub={failedCount > 0 ? "Review failed runs" : "No failures"}
            tone={failedCount > 0 ? "critical" : "default"}
            sparkline={[10, 8, 12, 6, 4, 3, failedCount > 0 ? 25 : 5]}
          />
          <KpiMetricCard
            label="Avg progress"
            value={`${avgProgress}%`}
            sub="Across all runs"
            sparkline={[30, 42, 50, 58, 62, 68, avgProgress]}
          />
        </div>
      )}

      {!runs.isLoading && !runs.isError && all.length > 0 && (
        <div className="mb-6 flex items-center gap-1 border-b border-border">
          {FILTERS.map((t) => {
            const active = filter === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setFilter(t.id)}
                className={cn(
                  "relative -mb-px flex items-center gap-2 px-4 py-2.5 text-sm transition-colors",
                  active ? "text-fg" : "text-fg-subtle hover:text-fg",
                )}
              >
                {t.label}
                <span
                  className={cn(
                    "mono rounded-full px-1.5 py-0.5 text-2xs",
                    active ? "bg-accent/15 text-accent" : "bg-surface-2 text-fg-subtle",
                  )}
                >
                  {countFor(t.id)}
                </span>
                {active && <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-accent" />}
              </button>
            );
          })}
        </div>
      )}

      {runs.isLoading ? (
        <LoadingPanel label="Loading collection runs…" />
      ) : runs.isError ? (
        <Card className="p-6">
          <EmptyState
            icon={AlertCircle}
            title="Collection API not available"
            description={
              <>
                The collection runs backend is not deployed yet. Use{" "}
                <Link href={ACQUIRE_HREF} className="text-accent hover:underline">
                  Acquire
                </Link>{" "}
                to download a kit, or start the updated console backend once{" "}
                <code className="mono rounded bg-surface-2 px-1">POST /api/runs</code> is enabled.
              </>
            }
            action={
              <Link href={RUNS_NEW_HREF}>
                <Button variant="secondary" icon={Play}>
                  Configure run
                </Button>
              </Link>
            }
          />
        </Card>
      ) : all.length === 0 ? (
        <Card className="p-6">
          <EmptyState
            icon={Play}
            title="No collection runs yet"
            description="Start a server-side collection to see live collector progress here."
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Link href={RUNS_NEW_HREF}>
                  <Button variant="primary-dark" icon={Plus}>
                    Run collection
                  </Button>
                </Link>
                <Link href={ACQUIRE_HREF}>
                  <Button variant="secondary">Open Acquire</Button>
                </Link>
              </div>
            }
          />
        </Card>
      ) : visible.length === 0 ? (
        <Card className="p-6">
          <EmptyState
            icon={Activity}
            title={`No ${filter === "running" ? "active" : filter} runs`}
            description="Try another filter or start a new collection."
            action={
              <Button variant="secondary" onClick={() => setFilter("all")}>
                Show all runs
              </Button>
            }
          />
        </Card>
      ) : (
        <Card className="glass-card-glow overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-surface-2/40">
                <tr>
                  <th className="table-header-cell-center">Status</th>
                  <th className="table-header-cell">Case ID</th>
                  <th className="table-header-cell">Platform</th>
                  <th className="table-header-cell">Provider</th>
                  <th className="table-header-cell">Started</th>
                  <th className="table-header-cell">Duration</th>
                  <th className="table-header-cell">Progress</th>
                  <th className="table-header-cell-center">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((run) => {
                  const { complete, total } = runProgress(run);
                  const provider =
                    (run.connection_id && connectionNames.get(run.connection_id)) || "—";
                  return (
                    <tr
                      key={run.run_id}
                      className="cursor-pointer border-b border-border/50 transition-colors hover:bg-surface-2/30"
                      onClick={() => router.push(runHref(run.run_id))}
                    >
                      <td className="table-cell-center">
                        <Badge className={cn("table-badge capitalize", statusTone(run.status))}>
                          {run.status}
                        </Badge>
                      </td>
                      <td className="table-cell">
                        <Link
                          href={caseHref(run.case_id)}
                          className="mono text-fg hover:text-accent"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {run.case_id}
                        </Link>
                      </td>
                      <td className="table-cell">
                        <span className="inline-flex items-center gap-2">
                          <CloudProviderIcon cloud={run.cloud as CasePlatform} />
                          {CASE_PLATFORM_LABELS[run.cloud as CasePlatform] ?? run.cloud}
                        </span>
                      </td>
                      <td className="table-cell-muted">{provider}</td>
                      <td className="table-cell-muted mono">
                        {(run.started_at ?? run.created_at)?.slice(0, 19) ?? "—"}
                      </td>
                      <td className="table-cell-muted mono">{fmtDuration(run)}</td>
                      <td className="table-cell">
                        {total > 0 ? (
                          <div className="min-w-[6rem] space-y-1.5">
                            <div className="mono text-sm text-fg-subtle">
                              {complete}/{total}
                            </div>
                            <SegmentedProgress
                              value={Math.round((complete / total) * 100)}
                              segments={4}
                            />
                          </div>
                        ) : (
                          <span className="mono text-fg-subtle">—</span>
                        )}
                      </td>
                      <td className="table-cell-center">
                        <div className="flex flex-wrap items-center justify-center gap-2" onClick={(e) => e.stopPropagation()}>
                          <Link href={runHref(run.run_id)}>
                            <Button variant="secondary" size="sm" icon={Eye}>
                              View
                            </Button>
                          </Link>
                          <Link href={caseHref(run.case_id)}>
                            <Button variant="ghost" size="sm" icon={ExternalLink}>
                              Case
                            </Button>
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
