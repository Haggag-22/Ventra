"use client";

import { getRunMatrix, runEventsUrl } from "@/lib/api";
import type { RunMatrix } from "@/lib/types";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const MAX_RECENT_EVENTS = 5;

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
  const [recentEvents, setRecentEvents] = useState<RunStreamEvent[]>([]);
  const esRef = useRef<EventSource | null>(null);

  const matrixQ = useQuery({
    queryKey: ["run-matrix", runId],
    queryFn: () => getRunMatrix(runId),
    refetchInterval: (q) => {
      const data = q.state.data as RunMatrix | undefined;
      if (sseConnected) return false;
      if (data?.status && TERMINAL.has(data.status)) return false;
      return 1000;
    },
    enabled: !!runId,
  });

  useEffect(() => {
    if (!runId) return;

    const pushEvent = (raw: string) => {
      try {
        const ev = JSON.parse(raw) as RunStreamEvent;
        setRecentEvents((prev) => [...prev.slice(-(MAX_RECENT_EVENTS - 1)), ev]);
      } catch {
        /* ignore malformed SSE payloads */
      }
    };

    const url = runEventsUrl(runId);
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setSseConnected(true);
    es.onmessage = (msg) => {
      setSseConnected(true);
      pushEvent(msg.data);
      void queryClient.invalidateQueries({ queryKey: ["run-matrix", runId] });
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
    };
    es.addEventListener("matrix", () => {
      setSseConnected(true);
      void queryClient.invalidateQueries({ queryKey: ["run-matrix", runId] });
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
    });
    es.onerror = () => {
      setSseConnected(false);
      es.close();
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [runId, queryClient]);

  return {
    matrix: matrixQ.data,
    isLoading: matrixQ.isLoading,
    error: matrixQ.error,
    sseConnected,
    recentEvents,
    refetch: matrixQ.refetch,
  };
}
