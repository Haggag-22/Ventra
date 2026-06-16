"use client";

import { usePagination } from "@/lib/pagination";
import { TablePager } from "@/components/table-pager";
import { cn } from "@/lib/utils";
import { ArrowDown, ArrowUp, ChevronsUpDown, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

export type DataColumn<T> = {
  key: string;
  label: string;
  align?: "left" | "right";
  /** Enables click-to-sort on this column. */
  sortable?: boolean;
  /** Sort/compare/filter value for the cell. */
  value: (row: T) => string | number;
  /** Cell content. Falls back to `value(row)` when omitted. */
  render?: (row: T) => ReactNode;
  /** Initial relative column width (px weight). */
  width?: number;
  min?: number;
  mono?: boolean;
  /** Let the cell wrap onto multiple lines instead of truncating. */
  wrap?: boolean;
};

type SortState = { key: string; dir: "asc" | "desc" };

export function DataTable<T>({
  columns,
  rows,
  getRowKey,
  initialSort,
  filterPlaceholder = "Filter…",
  emptyLabel = "Nothing to show.",
  pageSizeKey,
}: {
  columns: DataColumn<T>[];
  rows: T[];
  getRowKey: (row: T, index: number) => string;
  initialSort?: SortState;
  filterPlaceholder?: string;
  emptyLabel?: string;
  /** localStorage key to persist the chosen rows-per-page. */
  pageSizeKey?: string;
}) {
  const [sort, setSort] = useState<SortState | undefined>(initialSort);
  const [filter, setFilter] = useState("");
  const { page, setPage, pageSize, setPageSize } = usePagination(pageSizeKey);
  const [widths, setWidths] = useState<Record<string, number>>(() =>
    Object.fromEntries(columns.map((c) => [c.key, c.width ?? c.min ?? 120])),
  );
  const resizing = useRef<{ key: string; startX: number; startW: number } | null>(null);

  const startResize = useCallback(
    (col: DataColumn<T>, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const min = col.min ?? 60;
      resizing.current = {
        key: col.key,
        startX: e.clientX,
        startW: widths[col.key] ?? col.width ?? min,
      };
      const onMove = (ev: MouseEvent) => {
        if (!resizing.current) return;
        const delta = ev.clientX - resizing.current.startX;
        const w = Math.max(min, resizing.current.startW + delta);
        setWidths((prev) => ({ ...prev, [resizing.current!.key]: w }));
      };
      const onUp = () => {
        resizing.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    },
    [widths],
  );

  const toggleSort = (col: DataColumn<T>) => {
    if (!col.sortable) return;
    setSort((prev) =>
      prev?.key === col.key
        ? { key: col.key, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { key: col.key, dir: "desc" },
    );
  };

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) =>
      columns.some((c) => String(c.value(r)).toLowerCase().includes(needle)),
    );
  }, [rows, columns, filter]);

  const sorted = useMemo(() => {
    if (!sort) return filtered;
    const col = columns.find((c) => c.key === sort.key);
    if (!col) return filtered;
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const va = col.value(a);
      const vb = col.value(b);
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      return String(va).localeCompare(String(vb), undefined, { numeric: true }) * dir;
    });
  }, [filtered, columns, sort]);

  // Reset to the first page whenever the filter narrows/changes the result set.
  useEffect(() => setPage(0), [filter, setPage]);

  const paged = useMemo(
    () => sorted.slice(page * pageSize, page * pageSize + pageSize),
    [sorted, page, pageSize],
  );

  const totalWeight = columns.reduce((s, c) => s + (widths[c.key] ?? c.width ?? 120), 0);
  const colWidth = (key: string) => {
    const col = columns.find((c) => c.key === key);
    return `${widths[key] ?? col?.width ?? 120}px`;
  };

  return (
    <div>
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Search className="h-3.5 w-3.5 text-fg-subtle" />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={filterPlaceholder}
          className="h-6 w-full bg-transparent text-xs text-fg placeholder:text-fg-subtle/70 focus:outline-none"
        />
        <span className="mono shrink-0 text-2xs text-fg-subtle">
          {sorted.length}
          {sorted.length !== rows.length ? ` / ${rows.length}` : ""}
        </span>
      </div>

      <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
        <table
          className="ct-table ct-table-no-row-click w-full border-collapse text-left"
          style={{ tableLayout: "fixed", width: totalWeight, minWidth: "100%" }}
        >
          <colgroup>
            {columns.map((c) => (
              <col key={c.key} style={{ width: colWidth(c.key) }} />
            ))}
          </colgroup>
          <thead className="sticky top-0 z-10">
            <tr>
              {columns.map((c) => {
                const active = sort?.key === c.key;
                const Icon = !c.sortable
                  ? null
                  : !active
                    ? ChevronsUpDown
                    : sort?.dir === "asc"
                      ? ArrowUp
                      : ArrowDown;
                return (
                  <th key={c.key} className="relative">
                    <button
                      type="button"
                      onClick={() => toggleSort(c)}
                      disabled={!c.sortable}
                      className={cn(
                        "flex w-full items-center gap-1 pr-2",
                        c.align === "right" && "justify-end",
                        c.sortable && "cursor-pointer hover:text-fg",
                        active && "text-fg",
                      )}
                    >
                      <span className="truncate">{c.label}</span>
                      {Icon && (
                        <Icon
                          className={cn(
                            "h-3 w-3 shrink-0",
                            active ? "opacity-90" : "opacity-30",
                          )}
                        />
                      )}
                    </button>
                    <span
                      role="separator"
                      aria-orientation="vertical"
                      aria-label={`Resize ${c.label} column`}
                      onMouseDown={(e) => startResize(c, e)}
                      onClick={(e) => e.stopPropagation()}
                      className="ct-col-resize"
                    />
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {paged.map((row, i) => (
              <tr key={getRowKey(row, i)}>
                {columns.map((c) => {
                  const content = c.render ? c.render(row) : String(c.value(row));
                  const title =
                    typeof content === "string" && content !== "—" ? content : undefined;
                  return (
                    <td
                      key={c.key}
                      className={cn(
                        c.wrap ? "whitespace-normal break-all align-top" : "truncate",
                        c.align === "right" && "text-right",
                        c.mono && "mono text-fg-subtle",
                      )}
                      title={c.wrap ? undefined : title}
                    >
                      {content}
                    </td>
                  );
                })}
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-4 py-10 text-center text-sm text-fg-subtle">
                  {emptyLabel}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <TablePager
        page={page}
        pageSize={pageSize}
        total={sorted.length}
        shown={paged.length}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
      />
    </div>
  );
}
