"use client";



import { RunStatusBadge } from "@/components/badges";

import { CollectorMatrixTable } from "@/components/collector-matrix-table";

import { RunEventLog } from "@/components/run-event-log";

import { RunSimulatorStats } from "@/components/run-simulator-stats";

import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";

import { cancelRun, getRun } from "@/lib/api";

import { computeRunMatrixStats } from "@/lib/run-matrix-stats";

import { rerunScan, type RunMetaWithRequest } from "@/lib/rerun-run";

import { useElapsedTimer } from "@/lib/use-elapsed-timer";

import { useRunMatrix } from "@/lib/use-run-matrix";

import { caseHref, CONFIG_COLLECTION_HREF, runHref } from "@/lib/routes";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { AlertCircle, Ban, ExternalLink, Play, RotateCcw } from "lucide-react";

import Link from "next/link";

import { useParams, useRouter } from "next/navigation";

import { useMemo, useRef, useState, useEffect } from "react";



export default function RunDetailPage() {

  const params = useParams();

  const runId = decodeURIComponent(String(params.runId));

  const router = useRouter();

  const queryClient = useQueryClient();



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



  const { matrix, isLoading, error, sseConnected, allEvents } = useRunMatrix(runId);

  const [selectedCollector, setSelectedCollector] = useState<string | null>(null);
  const followLiveRef = useRef(true);



  const meta = metaQ.data;

  const rows = useMemo(() => matrix?.rows ?? [], [matrix?.rows]);

  const complete = matrix?.complete ?? meta?.collectors_complete ?? 0;

  const total = matrix?.total ?? meta?.collectors_total ?? rows.length;

  const status = matrix?.status ?? meta?.status ?? "pending";

  const terminal = status === "completed" || status === "failed" || status === "cancelled";

  const active = status === "running" || status === "pending";

  const cancelling = status === "cancelling";

  // A cancel that is in flight (cancelling) or done (cancelled) both collapse running/pending
  // rows to a failed "Cancelled" state in the matrix views.
  const runCancelled = status === "cancelled" || cancelling;



  const cancelMut = useMutation({

    mutationFn: () => cancelRun(runId),

    onSuccess: () => {

      queryClient.invalidateQueries({ queryKey: ["run", runId] });

      queryClient.invalidateQueries({ queryKey: ["runs"] });

    },

  });



  const rerunMut = useMutation({

    mutationFn: () => {

      if (!meta) throw new Error("Run not loaded");

      return rerunScan(meta as RunMetaWithRequest);

    },

    onSuccess: ({ run_id }) => {

      queryClient.invalidateQueries({ queryKey: ["runs"] });

      router.push(runHref(run_id));

    },

  });



  const stats = useMemo(

    () => computeRunMatrixStats(rows, complete, total, runCancelled),

    [rows, complete, total, runCancelled],

  );



  const elapsed = useElapsedTimer(

    meta?.started_at ?? meta?.created_at,

    !terminal,

    meta?.duration_ms,

  );



  const handleSelectCollector = (name: string) => {
    setSelectedCollector((prev) => {
      if (prev === name) {
        followLiveRef.current = true;
        return null;
      }
      followLiveRef.current = false;
      return name;
    });
  };

  const postCollectBusy =
    active &&
    stats.running === 0 &&
    stats.pending === 0 &&
    !rows.some((r) => r.name === "package" || r.name === "ingest");

  useEffect(() => {
    if (!active || !stats.activeCollector || !followLiveRef.current) return;
    setSelectedCollector(stats.activeCollector);
  }, [active, stats.activeCollector]);



  if (metaQ.isLoading && isLoading) {

    return (

      <div className="run-detail-page">

        <LoadingPanel label="Loading run…" />

      </div>

    );

  }



  if (metaQ.isError && error) {

    return (

      <div className="run-detail-page">

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

    <div className="run-detail-page">

      <header className="run-detail-header">

        <div className="min-w-0">

          <h1 className="page-title mono truncate">{runId}</h1>

          <p className="mt-2 flex flex-wrap items-center gap-2 text-xs text-fg-subtle">

            <RunStatusBadge status={status} />

            {!sseConnected && !terminal && <span>· polling</span>}

          </p>

        </div>

        <div className="flex shrink-0 flex-wrap gap-2">

          {terminal && meta?.case_id && (

            <Link href={caseHref(meta.case_id)}>

              <Button variant="secondary" icon={ExternalLink}>

                Open case

              </Button>

            </Link>

          )}

          {(active || cancelling) && (

            <Button

              variant="primary"

              icon={Ban}

              loading={cancelMut.isPending || cancelling}

              disabled={cancelMut.isPending}

              onClick={() => cancelMut.mutate()}

            >

              {cancelling || cancelMut.isPending ? "Cancelling…" : "Cancel"}

            </Button>

          )}

          {terminal && (

            <Button

              variant="primary"

              icon={RotateCcw}

              loading={rerunMut.isPending}

              disabled={rerunMut.isPending || !meta?.request}

              onClick={() => rerunMut.mutate()}

            >

              Re-run

            </Button>

          )}

        </div>

      </header>



      {meta?.error && (

        <div className="mb-4 rounded-lg border border-bad-red/30 bg-bad-red/10 px-4 py-3 text-sm text-bad-red">

          {meta.error}

        </div>

      )}

      {rerunMut.isError && (

        <div className="mb-4 rounded-lg border border-bad-red/30 bg-bad-red/10 px-4 py-3 text-sm text-bad-red">

          {rerunMut.error instanceof Error ? rerunMut.error.message : "Failed to re-run scan"}

        </div>

      )}



      {(rows.length > 0 || !terminal) && (

        <section className="run-detail-progress">

          <RunSimulatorStats

            stats={stats}

            elapsed={elapsed}

            live={sseConnected && !terminal}

          />

        </section>

      )}



      {!rows.length && !terminal ? (

        <Card className="glass-card p-8">

          <EmptyState

            icon={Play}

            title="Waiting for collector…"

            description="The run has started. Collector status will appear here as events arrive."

          />

        </Card>

      ) : !rows.length && terminal ? (

        <Card className="glass-card p-8">

          <EmptyState

            icon={AlertCircle}

            title="No collectors ran"

            description={meta?.error || "The run ended during preflight before any collector started. See the error above."}

          />

        </Card>

      ) : (

        <div className="run-detail-body">

          <section className="run-detail-collectors">

            <CollectorMatrixTable

              rows={rows}

              cloud={meta?.cloud}

              activeCollector={stats.activeCollector}

              selectedCollector={selectedCollector}

              onSelectCollector={handleSelectCollector}

              complete={stats.complete}

              total={stats.total}

              runCancelled={runCancelled}

            />

          </section>

          <section className="run-detail-events">

            {postCollectBusy ? (
              <div className="mb-2 rounded-lg border border-warn-amber/30 bg-warn-amber/10 px-3 py-2 text-xs text-fg">
                Collectors finished — packaging and ingesting evidence. This phase can take a
                long time on large runs. Detailed live logs appear on new runs after restarting{" "}
                <span className="mono">ventra dev</span>. Click a{" "}
                <strong>Seal evidence package</strong> or <strong>Ingest</strong> row when shown,
                or clear the log filter (×) to view the full run log.
              </div>
            ) : null}

            <RunEventLog
              events={allEvents}
              filterCollector={selectedCollector}
              filterRow={rows.find((r) => r.name === selectedCollector)}
              live={sseConnected && !terminal}
              onClearFilter={
                selectedCollector
                  ? () => {
                      followLiveRef.current = true;
                      setSelectedCollector(null);
                    }
                  : undefined
              }
            />

          </section>

        </div>

      )}

    </div>

  );

}

