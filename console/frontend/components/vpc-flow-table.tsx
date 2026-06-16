"use client";

import { Entity } from "@/components/pivot";
import { VpcFlowDrawer } from "@/components/vpc-flow-drawer";
import { Spinner } from "@/components/ui";
import { fmtBytes, fmtTimeCloudTrail } from "@/lib/format";
import {
  DEFAULT_VPC_FLOW_WIDTHS,
  VPC_FLOW_COLS,
  VPC_FLOW_WIDTHS_KEY,
  loadVpcFlowWidths,
  orderedVisibleVpcFlowCols,
  vpcFlowAction,
  vpcFlowActionTone,
  vpcFlowInterface,
  vpcFlowOutcomeTone,
  vpcFlowProtocol,
  type VpcFlowColKey,
} from "@/lib/vpc-flow-columns";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useCallback, useEffect, useRef, useState } from "react";

export function VpcFlowTable({
  events,
  loading,
  visibleColumns,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
  visibleColumns: VpcFlowColKey[];
}) {
  const columns = orderedVisibleVpcFlowCols(visibleColumns);
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState(DEFAULT_VPC_FLOW_WIDTHS);
  const resizing = useRef<{ key: VpcFlowColKey; startX: number; startW: number } | null>(null);

  useEffect(() => {
    setWidths(loadVpcFlowWidths());
  }, []);

  const persistWidths = useCallback((next: Record<VpcFlowColKey, number>) => {
    try {
      localStorage.setItem(VPC_FLOW_WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: VpcFlowColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = VPC_FLOW_COLS.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = {
        key,
        startX: e.clientX,
        startW: widths[key] ?? DEFAULT_VPC_FLOW_WIDTHS[key],
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
    (sum, c) => sum + (widths[c.key] ?? DEFAULT_VPC_FLOW_WIDTHS[c.key]),
    0,
  );

  const colWidth = (key: VpcFlowColKey) =>
    `${widths[key] ?? DEFAULT_VPC_FLOW_WIDTHS[key]}px`;

  const renderCell = (key: VpcFlowColKey, e: UnifiedEvent) => {
    const action = vpcFlowAction(e);

    switch (key) {
      case "timestamp":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {fmtTimeCloudTrail(e.timestamp)}
          </td>
        );
      case "action":
        return (
          <td key={key} className="mono truncate font-semibold">
            <span className={vpcFlowActionTone(action)}>{action}</span>
          </td>
        );
      case "source_ip":
        return (
          <td key={key} className="truncate" onClick={(ev) => ev.stopPropagation()}>
            {e.source_ip ? <Entity kind="ip" value={e.source_ip} /> : "—"}
          </td>
        );
      case "dest_ip":
        return (
          <td key={key} className="truncate" onClick={(ev) => ev.stopPropagation()}>
            {e.dest_ip ? <Entity kind="ip" value={e.dest_ip} /> : "—"}
          </td>
        );
      case "dest_port":
        return (
          <td key={key} className="mono truncate text-fg">
            {e.dest_port != null && e.dest_port > 0 ? e.dest_port : "—"}
          </td>
        );
      case "protocol":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {vpcFlowProtocol(e)}
          </td>
        );
      case "bytes":
        return (
          <td key={key} className="mono truncate text-fg">
            {e.dest_bytes != null && e.dest_bytes > 0 ? fmtBytes(e.dest_bytes) : "—"}
          </td>
        );
      case "outcome":
        return (
          <td key={key} className="mono truncate capitalize">
            <span className={cn("font-medium", vpcFlowOutcomeTone(e.event_outcome))}>
              {e.event_outcome || "—"}
            </span>
          </td>
        );
      case "interface":
        return (
          <td key={key} className="mono truncate text-fg-subtle" title={vpcFlowInterface(e) || undefined}>
            {vpcFlowInterface(e) || "—"}
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
                  <tr key={`${e.timestamp}-${e.source_ip}-${e.dest_ip}-${i}`} onClick={() => setSelected(e)}>
                    {columns.map((c) => renderCell(c.key, e))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {!loading && events.length === 0 && (
            <div className="px-4 py-16 text-center text-sm text-fg-subtle">
              No VPC flow records match the current filters.
            </div>
          )}
        </>
      )}

      <VpcFlowDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
