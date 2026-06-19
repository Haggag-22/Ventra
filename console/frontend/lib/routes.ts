import type { Cloud } from "./catalog";

/** Canonical URL for the cases list (outside any open case). */
export const CASES_HREF = "/cases";

export type AcquireHrefParams = {
  caseId?: string;
  cloud?: Cloud;
  /** Collector registry keys to pre-select in the kit cart. */
  collectors?: string[];
};

/** Build `/acquire` with optional case, cloud, and pre-selected collectors. */
export function acquireHref(params: AcquireHrefParams = {}): string {
  const sp = new URLSearchParams();
  if (params.caseId?.trim()) sp.set("case_id", params.caseId.trim());
  if (params.cloud) sp.set("cloud", params.cloud);
  if (params.collectors?.length) sp.set("collectors", params.collectors.join(","));
  const q = sp.toString();
  return q ? `/acquire?${q}` : "/acquire";
}
