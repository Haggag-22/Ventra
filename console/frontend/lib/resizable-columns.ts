"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type ColumnDef<K extends string> = {
  key: K;
  label: string;
  min: number;
};

export function useResizableColumns<K extends string>(
  cols: readonly ColumnDef<K>[],
  defaultWidths: Record<K, number>,
  storageKey: string,
) {
  const [widths, setWidths] = useState<Record<K, number>>(defaultWidths);
  const resizing = useRef<{ key: K; startX: number; startW: number } | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) setWidths({ ...defaultWidths, ...JSON.parse(raw) });
    } catch {
      /* ignore */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- load persisted widths once on mount
  }, []);

  const persistWidths = useCallback(
    (next: Record<K, number>) => {
      try {
        localStorage.setItem(storageKey, JSON.stringify(next));
      } catch {
        /* ignore */
      }
    },
    [storageKey],
  );

  const startResize = useCallback(
    (key: K, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = cols.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = { key, startX: e.clientX, startW: widths[key] ?? defaultWidths[key] };

      const onMove = (ev: MouseEvent) => {
        if (!resizing.current) return;
        const delta = ev.clientX - resizing.current.startX;
        const w = Math.max(min, resizing.current.startW + delta);
        setWidths((prev) => ({ ...prev, [key]: w }));
      };

      const onUp = () => {
        resizing.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        setWidths((prev) => {
          persistWidths(prev);
          return prev;
        });
      };

      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    },
    [cols, widths, defaultWidths, persistWidths],
  );

  const totalWeight = cols.reduce((sum, c) => sum + (widths[c.key] ?? defaultWidths[c.key]), 0);

  const colPct = (key: K) =>
    `${(((widths[key] ?? defaultWidths[key]) / totalWeight) * 100).toFixed(4)}%`;

  // Absolute pixel width for a column, and the table's total width. Using pixels (rather than
  // percentages that normalize to 100%) lets the table overflow its container so the wrapper's
  // horizontal scrollbar engages — and resizing a column wider actually widens the table.
  const colWidth = (key: K) => `${widths[key] ?? defaultWidths[key]}px`;

  return { widths, startResize, colPct, colWidth, totalWidth: totalWeight };
}
