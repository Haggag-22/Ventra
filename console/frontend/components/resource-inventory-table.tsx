"use client";

import { Entity } from "@/components/pivot";
import {
  columnsForResource,
  defaultResourceWidths,
  getInventoryRows,
  loadResourceWidths,
  resourcePrimaryId,
  resourceWidthsKey,
  type ResourceColumn,
  type ResourceRow,
} from "@/lib/resource-inventory-detail";
import { fmtNum } from "@/lib/format";
import type { InventoryResourceItem } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const ENTITY_KIND_IDS = new Set([
  "ec2_instances",
  "ec2_volumes",
  "ec2_snapshots",
  "ec2_images",
  "ec2_launch_templates",
  "ec2_enis",
  "ec2_security_groups",
  "s3_buckets",
  "vpc_count",
  "vpc_flow_logs",
]);

function PrimaryCell({ itemId, text }: { itemId: string; text: string }) {
  if (ENTITY_KIND_IDS.has(itemId) && text !== "—") {
    return <Entity kind="resource" value={text} />;
  }
  return <span>{text}</span>;
}

export function ResourceInventoryTable({
  item,
  data,
}: {
  item: InventoryResourceItem;
  data: unknown;
}) {
  const rows = getInventoryRows(data, item.key);
  const columns = useMemo(() => columnsForResource(item.id), [item.id]);
  const defaults = useMemo(() => defaultResourceWidths(columns), [columns]);

  const [widths, setWidths] = useState(defaults);
  const resizing = useRef<{ key: string; startX: number; startW: number } | null>(null);

  useEffect(() => {
    setWidths(loadResourceWidths(item.id, columns));
  }, [item.id, columns]);

  const persistWidths = useCallback(
    (next: Record<string, number>) => {
      try {
        localStorage.setItem(resourceWidthsKey(item.id), JSON.stringify(next));
      } catch {
        /* ignore */
      }
    },
    [item.id],
  );

  const startResize = useCallback(
    (col: ResourceColumn, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const min = col.min ?? 60;
      resizing.current = {
        key: col.key,
        startX: e.clientX,
        startW: widths[col.key] ?? defaults[col.key] ?? min,
      };

      const onMove = (ev: MouseEvent) => {
        if (!resizing.current) return;
        const delta = ev.clientX - resizing.current.startX;
        const w = Math.max(min, resizing.current.startW + delta);
        setWidths((prev) => ({ ...prev, [col.key]: w }));
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
    [widths, defaults, persistWidths],
  );

  const totalWeight = columns.reduce(
    (sum, c) => sum + (widths[c.key] ?? defaults[c.key] ?? c.min ?? 80),
    0,
  );

  const colPct = (key: string) => {
    const col = columns.find((c) => c.key === key);
    const w = widths[key] ?? defaults[key] ?? col?.min ?? 80;
    return `${((w / totalWeight) * 100).toFixed(4)}%`;
  };

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-2 px-0.5">
        <h3 className="text-sm font-semibold text-fg">{item.label}</h3>
        <span className="mono text-2xs text-fg-subtle">{fmtNum(rows.length)} in scope</span>
      </div>

      <div className="ct-panel">
        {rows.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-fg-subtle">
            None collected for this category.
          </div>
        ) : (
          <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
            <table
              className="ct-table ct-table-no-row-click w-full border-collapse text-left"
              style={{ tableLayout: "fixed" }}
            >
              <colgroup>
                {columns.map((c) => (
                  <col key={c.key} style={{ width: colPct(c.key) }} />
                ))}
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  {columns.map((c) => (
                    <th key={c.key} className="relative">
                      <span className="block truncate pr-2">{c.header}</span>
                      <span
                        role="separator"
                        aria-orientation="vertical"
                        aria-label={`Resize ${c.header} column`}
                        onMouseDown={(e) => startResize(c, e)}
                        onClick={(e) => e.stopPropagation()}
                        className="ct-col-resize"
                      />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row: ResourceRow, i) => (
                  <tr key={resourcePrimaryId(item, row) + i}>
                    {columns.map((col, ci) => {
                      const text = col.cell(row);
                      return (
                        <td
                          key={col.key}
                          className={cn("truncate", col.mono && "mono text-fg-subtle")}
                          title={text !== "—" ? text : undefined}
                        >
                          {ci === 0 ? (
                            <PrimaryCell itemId={item.id} text={text} />
                          ) : (
                            text
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
