"use client";

import { useParams, usePathname } from "next/navigation";
import { useSyncExternalStore } from "react";

/** The `_` segment that lib/static-export-params.ts exports case/run shells under. That module
 * reads artifacts/ with node:fs at build time, so it must not be imported into client code. */
const STATIC_PLACEHOLDER = "_";

/**
 * Read a dynamic route segment, falling back to the browser URL when the page was served from a
 * static-export placeholder shell (the packaged console, where `useParams()` returns "_").
 * `segment` is the zero-based index of the value in the path, e.g. 1 for `caseId` in
 * `/cases/<caseId>/cloudtrail`.
 */
export function useRouteParam(name: string, segment: number): string {
  const params = useParams();
  const pathname = usePathname();
  const raw = params?.[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value && value !== STATIC_PLACEHOLDER) return decodeURIComponent(value);
  const fromUrl = (pathname ?? "").split("/").filter(Boolean)[segment];
  return fromUrl ? decodeURIComponent(fromUrl) : "";
}

const noopSubscribe = () => () => {};

/**
 * False while React hydrates the static-export HTML, true afterwards (and on client-side
 * navigation). The "_" shells were pre-rendered with the placeholder, so a page that shows the
 * real ID must render placeholder-free markup until this is true, or React reports a hydration
 * mismatch (#418) and throws the static HTML away.
 */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false,
  );
}
