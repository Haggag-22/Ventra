"use client";

import { ContextDrawer } from "@/components/context-drawer";
import { Entity } from "@/components/pivot";
import { Spinner } from "@/components/ui";
import { findingOrigin, findingOriginClass } from "@/lib/finding-origin";
import { fmtTimeCloudTrail } from "@/lib/format";
import { SEVERITY_META } from "@/lib/severity";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useCallback, useEffect, useRef, useState } from "react";

const COLS = [
  { key: "timestamp", label: "Time (UTC)", min: 120 },
  { key: "severity", label: "Severity", min: 80 },
  { key: "finding_source", label: "Source", min: 100 },
  { key: "event_action", label: "Action", min: 140 },
  { key: "user_name", label: "Principal", min: 120 },
  { key: "source_ip", label: "Source IP", min: 120 },
  { key: "cloud_region", label: "Region", min: 80 },
] as const;

type ColKey = (typeof COLS)[number]["key"];

const DEFAULT_WIDTHS: Record<ColKey, number> = {
  timestamp: 180,
  severity: 88,
  finding_source: 110,
  event_action: 240,
  user_name: 180,
  source_ip: 160,
  cloud_region: 100,
};

const WIDTHS_KEY = "harbor.findings-table.widths.v2";

function loadWidths(): Record<ColKey, number> {
  if (typeof window === "undefined") return DEFAULT_WIDTHS;
  try {
    const raw = localStorage.getItem(WIDTHS_KEY);
    if (!raw) return DEFAULT_WIDTHS;
    return { ...DEFAULT_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_WIDTHS;
  }
}

export function FindingsTable({
  events,
  loading,
  emptyHint,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
  emptyHint?: React.ReactNode;
}) {
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState<Record<ColKey, number>>(DEFAULT_WIDTHS);
  const resizing = useRef<{ key: ColKey; startX: number; startW: number } | null>(null);

  useEffect(() => {
    setWidths(loadWidths());
  }, []);

  const persistWidths = useCallback((next: Record<ColKey, number>) => {
    try {
      localStorage.setItem(WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: ColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = COLS.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = { key, startX: e.clientX, startW: widths[key] ?? DEFAULT_WIDTHS[key] };

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
    [widths, persistWidths],
  );

  const totalWeight = COLS.reduce((sum, c) => sum + (widths[c.key] ?? DEFAULT_WIDTHS[c.key]), 0);

  const colPct = (key: ColKey) =>
    `${(((widths[key] ?? DEFAULT_WIDTHS[key]) / totalWeight) * 100).toFixed(4)}%`;

  return (
    <div className="relative">
      {loading && events.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Spinner />
        </div>
      ) : (
        <>
          <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
            <table className="ct-table w-full border-collapse text-left" style={{ tableLayout: "fixed" }}>
              <colgroup>
                {COLS.map((c) => (
                  <col key={c.key} style={{ width: colPct(c.key) }} />
                ))}
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  {COLS.map((c) => (
                    <th key={c.key} className="relative">
                      <span className="block truncate pr-2">{c.label}</span>
                      <span
                        role="separator"
                        aria-orientation="vertical"
                        aria-label={`Resize ${c.label || c.key} column`}
                        onMouseDown={(e) => startResize(c.key, e)}
                        onClick={(e) => e.stopPropagation()}
                        className="ct-col-resize"
                      />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => {
                  const origin = findingOrigin(e);
                  return (
                    <tr key={`${e.timestamp}-${i}`} onClick={() => setSelected(e)}>
                      <td className="mono truncate text-fg-subtle">
                        {fmtTimeCloudTrail(e.timestamp)}
                      </td>
                      <td className="truncate">
                        <span
                          className={cn(
                            "text-xs font-semibold",
                            (SEVERITY_META[e.event_severity] ?? SEVERITY_META.info).text,
                          )}
                        >
                          {(SEVERITY_META[e.event_severity] ?? SEVERITY_META.info).label}
                        </span>
                      </td>
                      <td className="truncate">
                        <span
                          className={cn("finding-origin-badge", findingOriginClass(origin))}
                          title={`Collector: ${e.harbor_source}`}
                        >
                          {origin}
                        </span>
                      </td>
                      <td className="truncate font-semibold text-fg" title={e.event_action || undefined}>
                        {e.event_action || e.message}
                      </td>
                      <td
                        className="overflow-hidden whitespace-nowrap"
                        title={e.user_name || undefined}
                        onClick={(ev) => ev.stopPropagation()}
                      >
                        {e.user_name ? (
                          <Entity kind="user" value={e.user_name} className="max-w-full" />
                        ) : (
                          <span className="text-fg-subtle">—</span>
                        )}
                      </td>
                      <td
                        className="overflow-hidden whitespace-nowrap"
                        title={e.source_ip || undefined}
                        onClick={(ev) => ev.stopPropagation()}
                      >
                        {e.source_ip ? (
                          <Entity kind="ip" value={e.source_ip} className="max-w-full" />
                        ) : (
                          <span className="text-fg-subtle">—</span>
                        )}
                      </td>
                      <td className="mono truncate text-fg-subtle">{e.cloud_region || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {!loading && events.length === 0 && (
            <div className="px-4 py-16 text-center text-sm text-fg-subtle">
              {emptyHint ?? "No findings match the current filters."}
            </div>
          )}
        </>
      )}

      <ContextDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
