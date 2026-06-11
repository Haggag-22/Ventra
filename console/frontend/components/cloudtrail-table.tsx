"use client";

import { CloudTrailDrawer } from "@/components/cloudtrail-drawer";
import { Spinner } from "@/components/ui";
import {
  CLOUDTRAIL_WIDTHS_KEY,
  DEFAULT_CLOUDTRAIL_WIDTHS,
  loadCloudTrailWidths,
  orderedVisibleCols,
  type CloudTrailColKey,
} from "@/lib/cloudtrail-columns";
import { fmtTimeCloudTrail } from "@/lib/format";
import {
  cloudTrailCategoryClass,
  cloudTrailEventCategory,
  shortService,
} from "@/lib/cloudtrail-json";
import type { UnifiedEvent } from "@/lib/types";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export function CloudTrailTable({
  events,
  loading,
  visibleColumns,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
  visibleColumns: CloudTrailColKey[];
}) {
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState(DEFAULT_CLOUDTRAIL_WIDTHS);
  const resizing = useRef<{ key: CloudTrailColKey; startX: number; startW: number } | null>(null);

  const cols = useMemo(() => orderedVisibleCols(visibleColumns), [visibleColumns]);

  useEffect(() => {
    setWidths(loadCloudTrailWidths());
  }, []);

  const persistWidths = useCallback((next: Record<CloudTrailColKey, number>) => {
    try {
      localStorage.setItem(CLOUDTRAIL_WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: CloudTrailColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = cols.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = { key, startX: e.clientX, startW: widths[key] ?? DEFAULT_CLOUDTRAIL_WIDTHS[key] };

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
    [widths, persistWidths, cols],
  );

  const totalWeight = cols.reduce(
    (sum, c) => sum + (widths[c.key] ?? DEFAULT_CLOUDTRAIL_WIDTHS[c.key]),
    0,
  );

  const colPct = (key: CloudTrailColKey) =>
    `${(((widths[key] ?? DEFAULT_CLOUDTRAIL_WIDTHS[key]) / totalWeight) * 100).toFixed(4)}%`;

  const renderCell = (key: CloudTrailColKey, e: UnifiedEvent, category: string) => {
    switch (key) {
      case "timestamp":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {fmtTimeCloudTrail(e.timestamp)}
          </td>
        );
      case "event_category":
        return (
          <td key={key} className="truncate">
            <span
              className={`ct-cat-badge ${cloudTrailCategoryClass(category)}`}
              title={`eventCategory: ${category}`}
            >
              {category}
            </span>
          </td>
        );
      case "event_action":
        return (
          <td key={key} className="truncate font-semibold text-fg">
            {e.event_action || e.message}
          </td>
        );
      case "user_name":
        return (
          <td key={key} className="mono truncate text-fg" title={e.user_name || undefined}>
            {e.user_name || "—"}
          </td>
        );
      case "source_ip":
        return (
          <td key={key} className="mono truncate text-fg">
            {e.source_ip || "—"}
          </td>
        );
      case "cloud_region":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {e.cloud_region || "—"}
          </td>
        );
      case "cloud_service":
        return (
          <td key={key} className="truncate text-fg-subtle">
            {shortService(
              (e.raw?.eventSource as string | undefined) ??
                (e.cloud_service ? `${e.cloud_service}.amazonaws.com` : ""),
            )}
          </td>
        );
      default:
        return null;
    }
  };

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
                {cols.map((c) => (
                  <col key={c.key} style={{ width: colPct(c.key) }} />
                ))}
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  {cols.map((c) => (
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
                      {cols.map((c) => renderCell(c.key, e, category))}
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
