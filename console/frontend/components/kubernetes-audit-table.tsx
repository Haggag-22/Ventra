"use client";

import { KubernetesAuditDrawer } from "@/components/kubernetes-audit-drawer";
import { Spinner } from "@/components/ui";
import {
  DEFAULT_K8S_AUDIT_WIDTHS,
  K8S_AUDIT_WIDTHS_KEY,
  loadK8sAuditWidths,
  orderedVisibleK8sCols,
  type K8sAuditColKey,
} from "@/lib/kubernetes-audit-columns";
import { fmtTimeCloudTrail } from "@/lib/format";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-bad-red/20 text-bad-red border-bad-red/30",
  high: "bg-warn-amber/20 text-warn-amber border-warn-amber/30",
  medium: "bg-accent/15 text-accent border-accent/30",
  low: "bg-surface-3 text-fg-subtle border-border",
  info: "bg-surface-3 text-fg-subtle border-border",
};

const OUTCOME_CLASS: Record<string, string> = {
  success: "text-ok-green",
  failure: "text-bad-red",
  unknown: "text-fg-subtle",
};

export function KubernetesAuditTable({
  events,
  loading,
  visibleColumns,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
  visibleColumns: K8sAuditColKey[];
}) {
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState(DEFAULT_K8S_AUDIT_WIDTHS);
  const resizing = useRef<{ key: K8sAuditColKey; startX: number; startW: number } | null>(null);

  const cols = useMemo(() => orderedVisibleK8sCols(visibleColumns), [visibleColumns]);

  useEffect(() => {
    setWidths(loadK8sAuditWidths());
  }, []);

  const persistWidths = useCallback((next: Record<K8sAuditColKey, number>) => {
    try {
      localStorage.setItem(K8S_AUDIT_WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: K8sAuditColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = cols.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = { key, startX: e.clientX, startW: widths[key] ?? DEFAULT_K8S_AUDIT_WIDTHS[key] };

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
    (sum, c) => sum + (widths[c.key] ?? DEFAULT_K8S_AUDIT_WIDTHS[c.key]),
    0,
  );

  const colWidth = (key: K8sAuditColKey) =>
    `${widths[key] ?? DEFAULT_K8S_AUDIT_WIDTHS[key]}px`;

  const renderCell = (key: K8sAuditColKey, e: UnifiedEvent) => {
    switch (key) {
      case "timestamp":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {fmtTimeCloudTrail(e.timestamp)}
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
      case "resource_id":
        return (
          <td key={key} className="mono truncate text-fg-subtle" title={e.resource_id || undefined}>
            {e.resource_id || "—"}
          </td>
        );
      case "event_outcome":
        return (
          <td key={key} className="truncate">
            <span className={cn("font-medium capitalize", OUTCOME_CLASS[e.event_outcome] ?? "text-fg")}>
              {e.event_outcome || "—"}
            </span>
          </td>
        );
      case "event_severity":
        return (
          <td key={key} className="truncate">
            <span
              className={cn(
                "inline-flex rounded border px-1.5 py-0.5 text-xs font-medium capitalize",
                SEVERITY_CLASS[e.event_severity] ?? SEVERITY_CLASS.info,
              )}
            >
              {e.event_severity || "—"}
            </span>
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
                {events.map((e, i) => (
                  <tr key={`${e.timestamp}-${i}`} onClick={() => setSelected(e)}>
                    {cols.map((c) => renderCell(c.key, e))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {!loading && events.length === 0 && (
            <div className="px-4 py-16 text-center text-sm text-fg-subtle">
              No audit events match the current filters.
            </div>
          )}
        </>
      )}

      <KubernetesAuditDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
