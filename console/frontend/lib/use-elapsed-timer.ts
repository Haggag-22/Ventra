"use client";

import { fmtElapsedLive } from "@/lib/run-matrix-stats";
import { useEffect, useState } from "react";

export function useElapsedTimer(
  startedAt: string | null | undefined,
  active: boolean,
  fallbackMs?: number | null,
): string {
  const [label, setLabel] = useState("—");

  useEffect(() => {
    if (!active) {
      if (fallbackMs != null && fallbackMs >= 0) {
        setLabel(fmtElapsedLive(fallbackMs));
      }
      return;
    }

    const startMs = startedAt ? Date.parse(startedAt) : Date.now();
    if (!Number.isFinite(startMs)) {
      setLabel("—");
      return;
    }

    const tick = () => setLabel(fmtElapsedLive(Math.max(0, Date.now() - startMs)));
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [startedAt, active, fallbackMs]);

  return label;
}
