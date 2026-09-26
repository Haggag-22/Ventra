"use client";

import { cn } from "@/lib/utils";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

export type SortDir = "asc" | "desc";
export type SortState = { key: string; dir: SortDir };

/** Click cycles a column desc → asc; a new column starts desc (newest / largest first). */
export function nextSort(prev: SortState | undefined, key: string): SortState {
  return prev?.key === key
    ? { key, dir: prev.dir === "asc" ? "desc" : "asc" }
    : { key, dir: "desc" };
}

export type SortValue = string | number | null | undefined;

/** Parse an ISO-ish timestamp for sorting; unparseable values sort as empty. */
export function timeValue(value: string | null | undefined): number | null {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/** Compare two cell values. Empty values always sort last, whatever the direction. */
export function compareSortValues(a: SortValue, b: SortValue, dir: SortDir): number {
  const aEmpty = a === null || a === undefined || a === "";
  const bEmpty = b === null || b === undefined || b === "";
  if (aEmpty || bEmpty) return aEmpty === bEmpty ? 0 : aEmpty ? 1 : -1;
  const sign = dir === "asc" ? 1 : -1;
  if (typeof a === "number" && typeof b === "number") return (a - b) * sign;
  return String(a).localeCompare(String(b), undefined, { numeric: true }) * sign;
}

/**
 * Client-side sorting for tables that hold all their rows in memory. Pass a stable
 * `value` accessor (module-level or `useCallback`) so the sort isn't recomputed every render.
 */
export function useClientSort<T>(
  rows: T[],
  value: (row: T, key: string) => SortValue,
  initial?: SortState,
) {
  const [sort, setSort] = useState<SortState | undefined>(initial);
  const toggle = useCallback((key: string) => setSort((prev) => nextSort(prev, key)), []);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    return [...rows].sort((a, b) =>
      compareSortValues(value(a, sort.key), value(b, sort.key), sort.dir),
    );
  }, [rows, sort, value]);
  return { sorted, sort, toggle, setSort };
}

/**
 * Header label with a sort toggle. Renders a plain label when `onSort` is missing,
 * so columns that can't be sorted keep the same layout.
 */
export function SortLabel({
  label,
  sortKey,
  sort,
  onSort,
  align,
  className,
}: {
  label: string;
  sortKey?: string;
  sort?: SortState;
  onSort?: (key: string) => void;
  align?: "left" | "right";
  className?: string;
}) {
  if (!sortKey || !onSort) {
    return (
      <span className={cn("block truncate pr-2", align === "right" && "text-right", className)}>
        {label}
      </span>
    );
  }
  const active = sort?.key === sortKey;
  const Icon = !active ? ChevronsUpDown : sort?.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onSort(sortKey);
      }}
      title={`Sort by ${label}`}
      className={cn(
        "flex w-full cursor-pointer items-center gap-1 pr-2 hover:text-fg",
        align === "right" && "justify-end",
        active && "text-fg",
        className,
      )}
    >
      <span className="truncate">{label}</span>
      <Icon className={cn("h-3 w-3 shrink-0", active ? "opacity-90" : "opacity-30")} />
    </button>
  );
}

/** `<th>` for the compact summary tables (`table-header-cell` styling) with a sort toggle. */
export function SortTh({
  label,
  sortKey,
  sort,
  onSort,
  align,
  className,
}: {
  label: string;
  sortKey: string;
  sort?: SortState;
  onSort: (key: string) => void;
  align?: "left" | "right";
  className?: string;
}) {
  const active = sort?.key === sortKey;
  return (
    <th
      className={cn(align === "right" ? "table-header-cell-right" : "table-header-cell", className)}
      aria-sort={active ? (sort?.dir === "asc" ? "ascending" : "descending") : undefined}
    >
      <SortLabel
        label={label}
        sortKey={sortKey}
        sort={sort}
        onSort={onSort}
        align={align}
        className="pr-0"
      />
    </th>
  );
}
