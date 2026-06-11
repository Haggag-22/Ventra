"use client";

import { CloudTrailDrawer } from "@/components/cloudtrail-drawer";
import { Spinner } from "@/components/ui";
import { fmtTimeCloudTrail } from "@/lib/format";
import {
  cloudTrailCategoryClass,
  cloudTrailEventCategory,
  shortService,
} from "@/lib/cloudtrail-json";
import type { UnifiedEvent } from "@/lib/types";
import { useCallback, useEffect, useRef, useState } from "react";

const COLS = [
  { key: "timestamp", label: "Time (UTC)", min: 120 },
  { key: "event_category", label: "Category", min: 90 },
  { key: "event_action", label: "Event", min: 140 },
  { key: "user_name", label: "Principal", min: 90 },
  { key: "source_ip", label: "Source IP", min: 100 },
  { key: "cloud_region", label: "Region", min: 80 },
  { key: "cloud_service", label: "Service", min: 70 },
] as const;

type ColKey = (typeof COLS)[number]["key"];

const DEFAULT_WIDTHS: Record<ColKey, number> = {
  timestamp: 190,
  event_category: 110,
  event_action: 260,
  user_name: 130,
  source_ip: 130,
  cloud_region: 110,
  cloud_service: 90,
};

const WIDTHS_KEY = "harbor.cloudtrail-table.widths";

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

export function CloudTrailTable({
  events,
  loading,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
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
                        aria-label={`Resize ${c.label} column`}
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
                  const category = cloudTrailEventCategory(e);
                  return (
                  <tr key={`${e.timestamp}-${i}`} onClick={() => setSelected(e)}>
                    <td className="mono truncate text-fg-subtle">
                      {fmtTimeCloudTrail(e.timestamp)}
                    </td>
                    <td className="truncate">
                      <span
                        className={`ct-cat-badge ${cloudTrailCategoryClass(category)}`}
                        title={`eventCategory: ${category}`}
                      >
                        {category}
                      </span>
                    </td>
                    <td className="truncate font-semibold text-fg">
                      {e.event_action || e.message}
                    </td>
                    <td className="mono truncate text-fg" title={e.user_name || undefined}>
                      {e.user_name || "—"}
                    </td>
                    <td className="mono truncate text-fg">{e.source_ip || "—"}</td>
                    <td className="mono truncate text-fg-subtle">{e.cloud_region || "—"}</td>
                    <td className="truncate text-fg-subtle">
                      {shortService(
                        (e.raw?.eventSource as string | undefined) ??
                          (e.cloud_service ? `${e.cloud_service}.amazonaws.com` : ""),
                      )}
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {!loading && events.length === 0 && (
            <div className="px-4 py-16 text-center text-sm text-fg-subtle">
              No events match the current filters.
            </div>
          )}
        </>
      )}

      <CloudTrailDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
