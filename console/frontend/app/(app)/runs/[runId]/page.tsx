"use client";

import { CollectorMatrixTable } from "@/components/collector-matrix-table";
import { RunCollectionSummary } from "@/components/run-collection-summary";
import { RunEventLog } from "@/components/run-event-log";
import { RunSimulatorStats } from "@/components/run-simulator-stats";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { getRun, listConnections } from "@/lib/api";
import { computeGapRows, computeRunMatrixStats } from "@/lib/run-matrix-stats";
import { useElapsedTimer } from "@/lib/use-elapsed-timer";
import { useRunMatrix } from "@/lib/use-run-matrix";
import { caseHref, CONFIG_COLLECTION_HREF, RUNS_NEW_HREF } from "@/lib/routes";
import { useQuery } from "@tanstack/react-query";
import { AlertCircle, ExternalLink, Play, RotateCcw } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo } from "react";

export default function RunDetailPage() {
  const params = useParams();
  const runId = decodeURIComponent(String(params.runId));

  const metaQ = useQuery({
    queryKey: ["run", runId],
    queryFn: () => getRun(runId),
    retry: false,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      if (s === "completed" || s === "failed" || s === "cancelled") return false;
      return 2000;
    },
  });

  const connections = useQuery({
    queryKey: ["config", "connections"],
    queryFn: listConnections,
    staleTime: 60_000,
    enabled: Boolean(metaQ.data?.connection_id),
  });

  const { matrix, isLoading, error, sseConnected, recentEvents } = useRunMatrix(runId);

  const meta = metaQ.data;
  const rows = useMemo(() => matrix?.rows ?? [], [matrix?.rows]);
  const complete = matrix?.complete ?? meta?.collectors_complete ?? 0;
  const total = matrix?.total ?? meta?.collectors_total ?? rows.length;
  const status = matrix?.status ?? meta?.status ?? "pending";
  const terminal = status === "completed" || status === "failed" || status === "cancelled";

  const stats = useMemo(
    () => computeRunMatrixStats(rows, complete, total),
    [rows, complete, total],
  );

  const gapRows = useMemo(
    () => computeGapRows(rows, status === "cancelled"),
    [rows, status],
  );

  const elapsed = useElapsedTimer(
    meta?.started_at ?? meta?.created_at,
    !terminal,
    meta?.duration_ms,
  );

  const connectionName = useMemo(() => {
    const id = meta?.connection_id;
    if (!id) return null;
    return connections.data?.connections.find((c) => c.id === id)?.name ?? id;
  }, [connections.data, meta?.connection_id]);

  if (metaQ.isLoading && isLoading) {
    return (
      <div className="px-6 py-8">
        <LoadingPanel label="Loading run…" />
      </div>
    );
  }

  if (metaQ.isError && error) {
    return (
      <div className="px-6 py-8">
        <Card className="p-6">
          <EmptyState
            icon={AlertCircle}
            title="Run not found"
            description={
              metaQ.error instanceof Error
                ? metaQ.error.message
                : "The runs API may not be enabled on this backend yet."
            }
            action={
              <Link href={CONFIG_COLLECTION_HREF}>
                <Button variant="secondary">Back to collection</Button>
              </Link>
            }
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="px-6 py-8">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="mono text-lg font-semibold">{runId}</h1>
          <p className="mt-1 text-sm text-fg-subtle">
            {meta?.cloud?.toUpperCase() ?? "—"} · case{" "}
            {meta?.case_id ? (
              <Link href={caseHref(meta.case_id)} className="mono text-accent hover:underline">
                {meta.case_id}
              </Link>
            ) : (
              "—"
            )}
            {connectionName && <> · provider {connectionName}</>}
            {meta?.account_id && <> · account {meta.masked_account ?? meta.account_id}</>}
          </p>
          <p className="mt-1 text-xs capitalize text-fg-subtle">
            Status: {status}
            {!sseConnected && !terminal && " · polling"}
            {sseConnected && !terminal && " · live stream"}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {terminal && meta?.case_id && (
            <Link href={caseHref(meta.case_id)}>
              <Button variant="primary-dark" icon={ExternalLink}>
                Open case
              </Button>
            </Link>
          )}
          <Link href={RUNS_NEW_HREF}>
            <Button variant="secondary" icon={RotateCcw}>
              Re-run
            </Button>
          </Link>
        </div>
      </div>

      {meta?.error && (
        <div className="mb-4 rounded-lg border border-bad-red/30 bg-bad-red/10 px-4 py-3 text-sm text-bad-red">
          {meta.error}
        </div>
      )}

      {(rows.length > 0 || !terminal) && (
        <div className="mb-6">
          <RunSimulatorStats
            stats={stats}
            elapsed={elapsed}
            live={sseConnected && !terminal}
          />
        </div>
      )}

      {!rows.length && !terminal ? (
        <Card className="p-8">
          <EmptyState
            icon={Play}
            title="Waiting for collector…"
            description="The run has started. Collector status will appear here as events arrive."
          />
        </Card>
      ) : (
        <div className="space-y-4">
          <CollectorMatrixTable
            rows={rows}
            activeCollector={stats.activeCollector}
            complete={stats.complete}
            total={stats.total}
          />
          <RunEventLog events={recentEvents} />
          {terminal && (
            <RunCollectionSummary
              stats={stats}
              status={status}
              caseId={meta?.case_id}
              gapRows={gapRows}
            />
          )}
        </div>
      )}
    </div>
  );
}
