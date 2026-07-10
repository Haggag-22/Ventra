"use client";

import { getRunEventLog, getRunMatrix, parseRunMatrix, runEventsUrl } from "@/lib/api";
import { mergeRunEvents } from "@/lib/collector-run-log";
import type { RunMatrix, RunMeta } from "@/lib/types";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const MAX_ALL_EVENTS = 5000;
const POLL_MS = 2000;
const SSE_RECONNECT_BASE_MS = 1000;
const SSE_RECONNECT_MAX_MS = 30_000;

export interface RunStreamEvent {
  type?: string;
  collector?: string;
  message?: string;
  status?: string;
  records?: number;
  ts?: string;
  [key: string]: unknown;
}

export function useRunMatrix(runId: string) {
  const queryClient = useQueryClient();
  const [sseConnected, setSseConnected] = useState(false);
  const [allEvents, setAllEvents] = useState<RunStreamEvent[]>([]);
  const esRef = useRef<EventSource | null>(null);

  const matrixQ = useQuery({
    queryKey: ["run-matrix", runId],
    queryFn: () => getRunMatrix(runId),
    // Keep polling while the run is active — SSE can be buffered by the Next.js proxy.
    refetchInterval: (q) => {
      const data = q.state.data as RunMatrix | undefined;
      if (data?.status && TERMINAL.has(data.status)) return false;
      return POLL_MS;
    },
    enabled: !!runId,
  });

  useEffect(() => {
    if (!runId) return;
    setAllEvents([]);
    let cancelled = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempt = 0;
    let eventPollTimer: ReturnType<typeof setInterval> | null = null;

    const hydrateEvents = () =>
      getRunEventLog(runId)
        .then(({ events }) => {
          if (cancelled) return;
          setAllEvents((prev) => mergeRunEvents(prev, events as RunStreamEvent[]));
        })
        .catch(() => {
          /* history endpoint may be unavailable on older backends */
        });

    void hydrateEvents();

    const pushEvent = (raw: string) => {
      try {
        const ev = JSON.parse(raw) as RunStreamEvent;
        setAllEvents((prev) => {
          const merged = mergeRunEvents(prev, [ev]);
          return merged.length > MAX_ALL_EVENTS
            ? merged.slice(-MAX_ALL_EVENTS)
            : merged;
        });
      } catch {
        /* ignore malformed SSE payloads */
      }
    };

    const applyMatrixPayload = (raw: string) => {
      try {
        const payload = JSON.parse(raw) as Record<string, unknown>;
        const matrix = parseRunMatrix(runId, payload);
        queryClient.setQueryData(["run-matrix", runId], matrix);
        queryClient.setQueryData(["run", runId], (prev: RunMeta | undefined) => {
          if (!prev) return prev;
          return {
            ...prev,
            status: matrix.status ?? prev.status,
            collectors_complete: matrix.complete,
            collectors_total: matrix.total,
          };
        });
      } catch {
        /* ignore malformed matrix payloads */
      }
    };

    const scheduleReconnect = () => {
      if (cancelled) return;
      const delay = Math.min(
        SSE_RECONNECT_MAX_MS,
        SSE_RECONNECT_BASE_MS * 2 ** reconnectAttempt,
      );
      reconnectAttempt += 1;
      reconnectTimer = setTimeout(connect, delay);
    };

    const connect = () => {
      if (cancelled) return;
      esRef.current?.close();

      const es = new EventSource(runEventsUrl(runId));
      esRef.current = es;

      es.onopen = () => {
        reconnectAttempt = 0;
        setSseConnected(true);
      };

      es.onmessage = (msg) => {
        setSseConnected(true);
        pushEvent(msg.data);
        try {
          const ev = JSON.parse(msg.data) as RunStreamEvent;
          if (ev.type === "finish" || ev.type === "start" || ev.type === "begin_run") {
            void queryClient.invalidateQueries({ queryKey: ["run-matrix", runId] });
          }
        } catch {
          /* ignore */
        }
        void queryClient.invalidateQueries({ queryKey: ["run", runId] });
      };

      es.addEventListener("matrix", (ev) => {
        setSseConnected(true);
        applyMatrixPayload((ev as MessageEvent).data);
      });

      es.onerror = () => {
        setSseConnected(false);
        es.close();
        if (esRef.current === es) esRef.current = null;
        scheduleReconnect();
      };
    };

    connect();

    eventPollTimer = setInterval(() => {
      const status = (
        queryClient.getQueryData(["run-matrix", runId]) as RunMatrix | undefined
      )?.status;
      if (status && TERMINAL.has(status)) return;
      void hydrateEvents();
    }, POLL_MS);

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (eventPollTimer) clearInterval(eventPollTimer);
      esRef.current?.close();
      esRef.current = null;
    };
  }, [runId, queryClient]);

  // Backfill the full persisted event history once the run is terminal. A fast preflight
  // failure emits begin_run/error around finalize, which the initial mount fetch and the
  // (now-closed) SSE stream can miss — leaving the log stuck on "no events yet".
  const terminalStatus =
    matrixQ.data?.status && TERMINAL.has(matrixQ.data.status) ? matrixQ.data.status : null;
  useEffect(() => {
    if (!runId || !terminalStatus) return;
    void getRunEventLog(runId)
      .then(({ events }) =>
        setAllEvents((prev) => mergeRunEvents(prev, events as RunStreamEvent[])),
      )
      .catch(() => {
        /* history endpoint unavailable — SSE-delivered events still show */
      });
  }, [runId, terminalStatus]);

  return {
    matrix: matrixQ.data,
    isLoading: matrixQ.isLoading,
    error: matrixQ.error,
    sseConnected,
    allEvents,
    refetch: matrixQ.refetch,
  };
}
