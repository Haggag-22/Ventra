"use client";

import { useCallback, useEffect, useState } from "react";

/** Rows-per-page choices shared by every table in the GUI. */
export const PAGE_SIZE_OPTIONS = [50, 100, 200, 500] as const;
export const DEFAULT_PAGE_SIZE = 100;

export type PageSize = (typeof PAGE_SIZE_OPTIONS)[number];

function readPersisted(storageKey: string | undefined, fallback: number): number {
  if (!storageKey || typeof window === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(storageKey);
    const n = raw ? Number.parseInt(raw, 10) : fallback;
    return PAGE_SIZE_OPTIONS.includes(n as PageSize) ? n : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Shared pagination state for any table. Optionally persists the chosen page size to
 * localStorage under `storageKey`. Changing the page size resets to the first page.
 */
export function usePagination(storageKey?: string, defaultSize: number = DEFAULT_PAGE_SIZE) {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSizeState] = useState(defaultSize);

  useEffect(() => {
    setPageSizeState(readPersisted(storageKey, defaultSize));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- load once on mount
  }, []);

  const setPageSize = useCallback(
    (next: number) => {
      setPageSizeState(next);
      setPage(0);
      if (storageKey && typeof window !== "undefined") {
        try {
          localStorage.setItem(storageKey, String(next));
        } catch {
          /* ignore */
        }
      }
    },
    [storageKey],
  );

  return { page, setPage, pageSize, setPageSize };
}
