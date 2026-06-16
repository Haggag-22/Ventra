"use client";

import { fmtNum } from "@/lib/format";
import { PAGE_SIZE_OPTIONS } from "@/lib/pagination";
import { cn } from "@/lib/utils";

/**
 * Shared footer pager used by every table: Prev/Next, range label, and a rows-per-page
 * selector (50 / 100 / 200 / 500). Styled with plain utilities so it works on any page,
 * not just the cloudtrail-view–scoped panels.
 *
 * `total` is the full result count; `shown` is how many rows are currently rendered.
 */
export function TablePager({
  page,
  pageSize,
  total,
  shown,
  onPageChange,
  onPageSizeChange,
  options = PAGE_SIZE_OPTIONS,
  className,
}: {
  page: number;
  pageSize: number;
  total: number;
  shown: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  options?: readonly number[];
  className?: string;
}) {
  if (total <= 0) return null;

  const offset = page * pageSize;
  const pageEnd = Math.min(offset + pageSize, total);
  const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
  const multiPage = total > pageSize;

  const btn =
    "inline-flex h-8 items-center rounded-md border border-border bg-surface px-3 text-xs font-medium text-fg-subtle transition-colors hover:border-border-strong hover:text-fg disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-border disabled:hover:text-fg-subtle";

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-3 border-t border-border px-3 py-2 text-xs text-fg-subtle",
        className,
      )}
    >
      {multiPage && (
        <>
          <button
            type="button"
            className={btn}
            disabled={page <= 0}
            onClick={() => onPageChange(Math.max(0, page - 1))}
          >
            ← Prev
          </button>
          <span className="mono">
            {fmtNum(offset + 1)}–{fmtNum(pageEnd)} of {fmtNum(total)}
          </span>
          <button
            type="button"
            className={btn}
            disabled={page >= lastPage}
            onClick={() => onPageChange(page + 1)}
          >
            Next →
          </button>
        </>
      )}

      <label className="ml-auto flex items-center gap-2">
        Rows per page
        <select
          className="h-8 cursor-pointer rounded-md border border-border bg-surface px-2 text-xs text-fg focus:border-accent focus:outline-none"
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number.parseInt(e.target.value, 10))}
          aria-label="Rows per page"
        >
          {options.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>

      <span>Showing {fmtNum(shown)} rows</span>
    </div>
  );
}
