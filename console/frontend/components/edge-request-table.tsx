"use client";

import { EdgeRequestDrawer } from "@/components/edge-request-drawer";
import { Entity } from "@/components/pivot";
import { Spinner } from "@/components/ui";
import {
  DEFAULT_EDGE_REQUEST_WIDTHS,
  EDGE_REQUEST_COLS,
  EDGE_REQUEST_WIDTHS_KEY,
  EDGE_SOURCE_CHIP,
  EDGE_SOURCE_LABEL,
  edgeHttpStatus,
  edgeStatusTone,
  loadEdgeRequestWidths,
  orderedVisibleEdgeRequestCols,
  type EdgeRequestColKey,
} from "@/lib/edge-request-columns";
import { fmtTimeCloudTrail } from "@/lib/format";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useCallback, useEffect, useRef, useState } from "react";

export function EdgeRequestTable({
  events,
  loading,
  visibleColumns,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
  visibleColumns: EdgeRequestColKey[];
}) {
  const columns = orderedVisibleEdgeRequestCols(visibleColumns);
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState(DEFAULT_EDGE_REQUEST_WIDTHS);
  const resizing = useRef<{ key: EdgeRequestColKey; startX: number; startW: number } | null>(null);

  useEffect(() => {
    setWidths(loadEdgeRequestWidths());
  }, []);

  const persistWidths = useCallback((next: Record<EdgeRequestColKey, number>) => {
    try {
      localStorage.setItem(EDGE_REQUEST_WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: EdgeRequestColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = EDGE_REQUEST_COLS.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = {
        key,
        startX: e.clientX,
        startW: widths[key] ?? DEFAULT_EDGE_REQUEST_WIDTHS[key],
      };

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

  const totalWeight = columns.reduce(
    (sum, c) => sum + (widths[c.key] ?? DEFAULT_EDGE_REQUEST_WIDTHS[c.key]),
    0,
  );

  const colWidth = (key: EdgeRequestColKey) =>
    `${widths[key] ?? DEFAULT_EDGE_REQUEST_WIDTHS[key]}px`;

  const renderCell = (key: EdgeRequestColKey, e: UnifiedEvent) => {
    const status = edgeHttpStatus(e);
    const source = e.ventra_source;

    switch (key) {
      case "timestamp":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {fmtTimeCloudTrail(e.timestamp)}
          </td>
        );
      case "source":
        return (
          <td key={key} className="truncate">
            <span
              className={cn(
                "inline-flex rounded-md border px-1.5 py-0.5 text-2xs font-semibold uppercase",
                EDGE_SOURCE_CHIP[source] ?? "border-border bg-surface-2 text-fg-subtle",
              )}
            >
              {EDGE_SOURCE_LABEL[source] ?? source}
            </span>
          </td>
        );
      case "method":
        return (
          <td key={key} className="mono truncate font-medium text-fg">
            {e.event_action || "—"}
          </td>
        );
      case "request":
        return (
          <td key={key} className="truncate text-fg" title={e.message}>
            {e.message || "—"}
          </td>
        );
      case "client_ip":
        return (
          <td key={key} className="truncate" onClick={(ev) => ev.stopPropagation()}>
            {e.source_ip ? <Entity kind="ip" value={e.source_ip} /> : "—"}
          </td>
        );
      case "status":
        return (
          <td key={key} className="mono truncate">
            {status ? (
              <span className={cn("font-semibold", edgeStatusTone(status))}>{status}</span>
            ) : (
              "—"
            )}
          </td>
        );
      case "resource":
        return (
          <td key={key} className="mono truncate text-fg-subtle" title={e.resource_id || undefined}>
            {e.resource_id || "—"}
          </td>
        );
      case "region":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {e.cloud_region || "—"}
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
            <table
              className="ct-table w-full border-collapse text-left"
              style={{ tableLayout: "fixed", width: totalWeight, minWidth: "100%" }}
            >
              <colgroup>
                {columns.map((c) => (
                  <col key={c.key} style={{ width: colWidth(c.key) }} />
                ))}
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  {columns.map((c) => (
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
                {events.map((e, i) => (
                  <tr key={`${e.timestamp}-${e.ventra_source}-${i}`} onClick={() => setSelected(e)}>
                    {columns.map((c) => renderCell(c.key, e))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {!loading && events.length === 0 && (
            <div className="px-4 py-16 text-center text-sm text-fg-subtle">
              No edge requests match the current filters.
            </div>
          )}
        </>
      )}

      <EdgeRequestDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
