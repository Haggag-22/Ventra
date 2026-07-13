"use client";

import { RunStatusBadge } from "@/components/badges";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { KpiMetricCard, SegmentedProgress } from "@/components/stat";
import { cancelRun, listConnections, listRuns } from "@/lib/api";
import { CASE_PLATFORM_LABELS, type CasePlatform } from "@/lib/catalog";
import { fmtTime } from "@/lib/format";
import { rerunScan, type RunMetaWithRequest } from "@/lib/rerun-run";
import {
  acquireRunHref,
  ACQUIRE_HREF,
  caseHref,
  runHref,
} from "@/lib/routes";
import { readLastConnection } from "@/lib/provider-storage";
import type { RunMeta, RunStatus } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  Ban,
  ExternalLink,
  Eye,
  Play,
  Plus,
  RotateCcw,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useMemo, useState } from "react";

type StatusFilter = "all" | "running" | "completed" | "failed" | "cancelled";

const FILTERS: { id: StatusFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "running", label: "Running" },
  { id: "completed", label: "Completed" },
  { id: "failed", label: "Failed" },
  { id: "cancelled", label: "Cancelled" },
];

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

function isLiveRun(status: RunStatus): boolean {
  return status === "running" || status === "pending" || status === "cancelling";
}

function matchesFilter(status: RunStatus, filter: StatusFilter): boolean {
  if (filter === "all") return true;
  if (filter === "running") return isLiveRun(status);
  return status === filter;
}

function isActiveRun(status: RunStatus): boolean {
  return status === "running" || status === "pending";
}

function RunRowActions({ run }: { run: RunMeta }) {
  const queryClient = useQueryClient();
  const router = useRouter();
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [rerunError, setRerunError] = useState("");

  const cancelMut = useMutation({
    mutationFn: () => cancelRun(run.run_id),
    onMutate: () => setCancellingId(run.run_id),
    onSettled: () => setCancellingId(null),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["runs"] }),
  });

  const rerunMut = useMutation({
    mutationFn: () => rerunScan(run as RunMetaWithRequest),
    onMutate: () => setRerunError(""),
    onSuccess: ({ run_id }) => {
      queryClient.invalidateQueries({ queryKey: ["runs"] });
      router.push(runHref(run_id));
    },
    onError: (e: unknown) =>
      setRerunError(e instanceof Error ? e.message : "Failed to re-run scan"),
  });

  const active = isActiveRun(run.status);
  const cancelling = run.status === "cancelling";
  const loading = cancellingId === run.run_id || cancelMut.isPending;
  const canCancel = active || cancelling;
  const canRerun = !active && !cancelling;

  return (
    <div className="flex flex-wrap items-center justify-center gap-2">
      {canCancel && (
        <Button
          variant="primary"
          size="sm"
          icon={Ban}
          loading={loading}
          disabled={loading}
          onClick={() => cancelMut.mutate()}
        >
          {cancelling || loading ? "Cancelling…" : "Cancel"}
        </Button>
      )}
      {canRerun && (
        <Button
          variant="secondary"
          size="sm"
          icon={RotateCcw}
          loading={rerunMut.isPending}
          disabled={rerunMut.isPending || !run.request}
          onClick={() => rerunMut.mutate()}
          title={
            !run.request
              ? "This run has no saved configuration to re-run."
              : rerunError || "Re-run this scan with the same configuration"
          }
        >
          Re-run
        </Button>
      )}
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
  );
}

export default function CollectionPage() {
  const router = useRouter();
  const [filter, setFilter] = useState<StatusFilter>("all");
  const newRunHref = acquireRunHref(readLastConnection());

  // Clicking a row always opens that existing run — it never starts a new scan. Re-running is
  // an explicit per-row "Re-run" button (see RunRowActions).
  const handleRowClick = useCallback(
    (run: RunMeta) => {
      router.push(runHref(run.run_id));
    },
    [router],
  );

  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: listRuns,
    retry: false,
    refetchInterval: (q) => {
      const rows = q.state.data?.runs ?? [];
      const active = rows.some((r) => isLiveRun(r.status));
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
            Scans
          </h1>
        </div>
        <Link href={newRunHref}>
          <Button variant="primary" icon={Plus}>
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
            tone="cta"
          />
          <KpiMetricCard
            label="Completed"
            value={completedCount}
            sub={all.length > 0 ? `${Math.round((completedCount / all.length) * 100)}% success rate` : "—"}
            tone="success"
          />
          <KpiMetricCard
            label="Failed"
            value={failedCount}
            sub={failedCount > 0 ? "Review failed runs" : "No failures"}
            tone="critical"
          />
          <KpiMetricCard
            label="Avg progress"
            value={`${avgProgress}%`}
            sub="Across all runs"
            tone="cta"
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
              <Link href={newRunHref}>
                <Button variant="secondary" icon={Play}>
                  Open Acquire
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
            description="Start a Ventra Console collection to see live collector progress here."
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Link href={newRunHref}>
                  <Button variant="primary" icon={Plus}>
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
              <thead>
                <tr className="table-head-row">
                  <th className="table-header-cell-center">Status</th>
                  <th className="table-header-cell">Case ID</th>
                  <th className="table-header-cell-center">Platform</th>
                  <th className="table-header-cell">Authentication</th>
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
                      onClick={() => handleRowClick(run)}
                    >
                      <td className="table-cell-center">
                        <RunStatusBadge status={run.status} />
                      </td>
                      <td className="table-cell">
                        <Link
                          href={caseHref(run.case_id)}
                          className="text-fg hover:text-accent"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {run.case_id}
                        </Link>
                      </td>
                      <td className="table-cell-center">
                        <span
                          className="inline-flex justify-center"
                          title={CASE_PLATFORM_LABELS[run.cloud as CasePlatform] ?? run.cloud}
                        >
                          <CloudProviderIcon cloud={run.cloud as CasePlatform} />
                        </span>
                      </td>
                      <td className="table-cell-muted">{provider}</td>
                      <td className="table-cell-muted mono">
                        {fmtTime(run.started_at ?? run.created_at)}
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
                      <td className="table-cell-center" onClick={(e) => e.stopPropagation()}>
                        <RunRowActions run={run} />
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
