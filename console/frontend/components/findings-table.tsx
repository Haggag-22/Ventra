"use client";

import { ContextDrawer } from "@/components/context-drawer";
import { Entity } from "@/components/pivot";
import { Spinner } from "@/components/ui";
import { findingClass, findingClassClass } from "@/lib/finding-class";
import {
  ALL_FINDING_COL_KEYS,
  DEFAULT_FINDING_WIDTHS,
  FINDING_COLS,
  FINDING_WIDTHS_KEY,
  loadFindingWidths,
  orderedVisibleFindingCols,
  type FindingColKey,
} from "@/lib/findings-columns";
import { findingOrigin, findingOriginClass } from "@/lib/finding-origin";
import { fmtTimeCloudTrail } from "@/lib/format";
import { SEVERITY_META } from "@/lib/severity";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

function renderCell(
  key: FindingColKey,
  e: UnifiedEvent,
  origin: ReturnType<typeof findingOrigin>,
  cls: ReturnType<typeof findingClass>,
) {
  switch (key) {
    case "timestamp":
      return (
        <td key={key} className="mono truncate text-fg-subtle">
          {fmtTimeCloudTrail(e.timestamp)}
        </td>
      );
    case "severity":
      return (
        <td key={key} className="truncate">
          <span
            className={cn(
              "text-xs font-semibold",
              (SEVERITY_META[e.event_severity] ?? SEVERITY_META.info).text,
            )}
          >
            {(SEVERITY_META[e.event_severity] ?? SEVERITY_META.info).label}
          </span>
        </td>
      );
    case "finding_source":
      return (
        <td key={key} className="truncate">
          <span
            className={cn("finding-origin-badge", findingOriginClass(origin))}
            title={`Collector: ${e.ventra_source}`}
          >
            {origin}
          </span>
        </td>
      );
    case "finding_class":
      return (
        <td key={key} className="truncate">
          <span className={cn("finding-class-badge", findingClassClass(cls))}>{cls}</span>
        </td>
      );
    case "event_action":
      return (
        <td key={key} className="truncate font-semibold text-fg" title={e.event_action || undefined}>
          {e.event_action || e.message}
        </td>
      );
    case "user_name":
      return (
        <td
          key={key}
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
      );
    case "source_ip":
      return (
        <td
          key={key}
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
      );
    case "cloud_region":
      return (
        <td key={key} className="mono truncate text-fg-subtle">
          {e.cloud_region || "—"}
        </td>
      );
    default:
      return null;
  }
}

export function FindingsTable({
  events,
  loading,
  emptyHint,
  visibleColumns = ALL_FINDING_COL_KEYS,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
  emptyHint?: React.ReactNode;
  visibleColumns?: FindingColKey[];
}) {
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState<Record<FindingColKey, number>>(DEFAULT_FINDING_WIDTHS);
  const resizing = useRef<{ key: FindingColKey; startX: number; startW: number } | null>(null);

  const cols = useMemo(() => orderedVisibleFindingCols(visibleColumns), [visibleColumns]);

  useEffect(() => {
    setWidths(loadFindingWidths());
  }, []);

  const persistWidths = useCallback((next: Record<FindingColKey, number>) => {
    try {
      localStorage.setItem(FINDING_WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: FindingColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = FINDING_COLS.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = {
        key,
        startX: e.clientX,
        startW: widths[key] ?? DEFAULT_FINDING_WIDTHS[key],
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

  const totalWeight = cols.reduce(
    (sum, c) => sum + (widths[c.key] ?? DEFAULT_FINDING_WIDTHS[c.key]),
    0,
  );

  const colWidth = (key: FindingColKey) =>
    `${widths[key] ?? DEFAULT_FINDING_WIDTHS[key]}px`;

  return (
    <div className="relative">
      {loading && events.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Spinner />
        </div>
      ) : (
        <>
          <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
            <table className="ct-table w-full border-collapse text-left" style={{ tableLayout: "fixed", width: totalWeight, minWidth: "100%" }}>
              <colgroup>
                {cols.map((c) => (
                  <col key={c.key} style={{ width: colWidth(c.key) }} />
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
                  const origin = findingOrigin(e);
                  const cls = findingClass(e);
                  return (
                    <tr key={`${e.timestamp}-${i}`} onClick={() => setSelected(e)}>
                      {cols.map((c) => renderCell(c.key, e, origin, cls))}
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
