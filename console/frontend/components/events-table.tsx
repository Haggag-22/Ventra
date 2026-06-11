"use client";

import { fmtTimeShort } from "@/lib/format";
import { findingOrigin, findingOriginClass } from "@/lib/finding-origin";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { ArrowDown, ArrowUp } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { OutcomeBadge, SeverityDot } from "./badges";
import { ContextDrawer } from "./context-drawer";
import { Entity } from "./pivot";

export interface EventsTableProps {
  events: UnifiedEvent[];
  loading?: boolean;
  sort?: string;
  order?: string;
  onSort?: (col: string) => void;
  emptyHint?: React.ReactNode;
  compact?: boolean;
  showFindingSource?: boolean;
}

const BASE_COLS: { key: string; label: string; sortable?: boolean; resizable?: boolean; min?: number }[] = [
  { key: "timestamp", label: "Time (UTC)", sortable: true, resizable: true, min: 90 },
  { key: "sev", label: "", resizable: false, min: 28 },
  { key: "event_action", label: "Action", sortable: true, resizable: true, min: 120 },
  { key: "user_name", label: "Principal", sortable: true, resizable: true, min: 100 },
  { key: "source_ip", label: "Source IP", sortable: true, resizable: true, min: 110 },
  { key: "cloud_region", label: "Region", resizable: true, min: 80 },
  { key: "outcome", label: "", resizable: true, min: 56 },
];

const SOURCE_COL = {
  key: "finding_source",
  label: "Source",
  sortable: false,
  resizable: true,
  min: 100,
};

const DEFAULT_WIDTHS: Record<string, number> = {
  timestamp: 120,
  sev: 28,
  finding_source: 120,
  event_action: 240,
  user_name: 160,
  source_ip: 140,
  cloud_region: 100,
  outcome: 72,
};

const WIDTHS_KEY = "harbor.events-table.widths";

function loadWidths(): Record<string, number> {
  if (typeof window === "undefined") return DEFAULT_WIDTHS;
  try {
    const raw = localStorage.getItem(WIDTHS_KEY);
    if (!raw) return DEFAULT_WIDTHS;
    return { ...DEFAULT_WIDTHS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_WIDTHS;
  }
}

export function EventsTable({
  events,
  loading,
  sort,
  order,
  onSort,
  emptyHint,
  compact,
  showFindingSource,
}: EventsTableProps) {
  const cols = useMemo(
    () =>
      showFindingSource
        ? [BASE_COLS[0], BASE_COLS[1], SOURCE_COL, ...BASE_COLS.slice(2)]
        : BASE_COLS,
    [showFindingSource],
  );

  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState(DEFAULT_WIDTHS);
  const resizing = useRef<{ key: string; startX: number; startW: number } | null>(null);

  useEffect(() => {
    setWidths(loadWidths());
  }, []);

  const persistWidths = useCallback((next: Record<string, number>) => {
    try {
      localStorage.setItem(WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: string, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = cols.find((c) => c.key === key);
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
    [widths, persistWidths, cols],
  );

  const tableWidth = cols.reduce((sum, c) => sum + (widths[c.key] ?? DEFAULT_WIDTHS[c.key]), 0);

  return (
    <div className="relative">
      <div className="overflow-x-auto">
        <table
          className="border-collapse text-sm"
          style={{ tableLayout: "fixed", width: Math.max(tableWidth, 640) }}
        >
          <colgroup>
            {cols.map((c) => (
              <col key={c.key} style={{ width: widths[c.key] ?? DEFAULT_WIDTHS[c.key] }} />
            ))}
          </colgroup>
          <thead className="sticky top-0 z-10 bg-surface">
            <tr className="border-b border-border text-left">
              {cols.map((c) => (
                <th
                  key={c.key}
                  className={cn(
                    "relative px-3 py-2 text-2xs font-medium uppercase tracking-wide text-fg-subtle",
                    c.sortable && onSort && "cursor-pointer select-none hover:text-fg",
                  )}
                  onClick={() => c.sortable && onSort?.(c.key)}
                >
                  <span className="inline-flex items-center gap-1 truncate pr-1">
                    {c.label}
                    {sort === c.key &&
                      (order === "desc" ? (
                        <ArrowDown className="h-3 w-3 shrink-0" />
                      ) : (
                        <ArrowUp className="h-3 w-3 shrink-0" />
                      ))}
                  </span>
                  {c.resizable !== false && (
                    <span
                      role="separator"
                      aria-orientation="vertical"
                      aria-label={`Resize ${c.label || c.key} column`}
                      onMouseDown={(e) => startResize(c.key, e)}
                      onClick={(e) => e.stopPropagation()}
                      className="absolute right-0 top-0 z-20 h-full w-1.5 cursor-col-resize touch-none hover:bg-accent/40"
                    />
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => {
              const origin = showFindingSource ? findingOrigin(e) : "";
              return (
              <tr
                key={`${e.timestamp}-${i}`}
                onClick={() => setSelected(e)}
                className={cn(
                  "row-hover cursor-pointer border-b border-border/60",
                  compact ? "h-8" : "h-10",
                  selected === e && "bg-accent/8",
                )}
              >
                <td className="px-3 mono text-2xs text-fg-subtle whitespace-nowrap overflow-hidden text-ellipsis">
                  {fmtTimeShort(e.timestamp)}
                </td>
                <td className="px-1">
                  <SeverityDot severity={e.event_severity} />
                </td>
                {showFindingSource && (
                  <td className="px-3 overflow-hidden">
                    <span
                      className={cn("finding-origin-badge", findingOriginClass(origin))}
                      title={`Collector: ${e.harbor_source}`}
                    >
                      {origin}
                    </span>
                  </td>
                )}
                <td className="px-3 overflow-hidden">
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className="mono text-xs text-fg truncate min-w-0"
                      title={e.event_action}
                    >
                      {e.event_action || e.message}
                    </span>
                  </div>
                </td>
                <td className="px-3 overflow-hidden" onClick={(ev) => ev.stopPropagation()}>
                  {e.user_name ? (
                    <Entity kind="user" value={e.user_name} truncate className="max-w-full" />
                  ) : (
                    <span className="text-fg-subtle text-xs">—</span>
                  )}
                </td>
                <td className="px-3 overflow-hidden" onClick={(ev) => ev.stopPropagation()}>
                  {e.source_ip ? (
                    <Entity kind="ip" value={e.source_ip} truncate className="max-w-full" />
                  ) : (
                    <span className="text-fg-subtle text-xs">—</span>
                  )}
                </td>
                <td className="px-3 mono text-2xs text-fg-subtle truncate overflow-hidden">
                  {e.cloud_region || "—"}
                </td>
                <td className="px-3 overflow-hidden">
                  <OutcomeBadge outcome={e.event_outcome} />
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {!loading && events.length === 0 && (
        <div className="px-4 py-12 text-center text-sm text-fg-subtle">
          {emptyHint ?? "No events match the current filters."}
        </div>
      )}

      <ContextDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
