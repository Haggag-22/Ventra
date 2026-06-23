"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";
import type { EventParams } from "./api";

// Every filter/selection lives in the URL so views are shareable. This hook reads the current
// search params into an EventParams object and writes changes back via router.replace.

const ARRAY_KEYS = new Set([
  "source",
  "severity",
  "category",
  "trail_category",
  "finding_class",
  "actions",
  "regions",
  "services",
  "users",
  "outcomes",
]);

export function useFilters() {
  const router = useRouter();
  const pathname = usePathname();
  const sp = useSearchParams();

  const params = useMemo<EventParams>(() => {
    const out: EventParams = {};
    for (const key of [
      "q",
      "action",
      "user",
      "user_type",
      "ip",
      "outcome",
      "region",
      "service",
      "kind",
      "ua_category",
      "related_ip",
      "related_user",
      "related_resource",
      "since",
      "until",
      "sort",
      "order",
    ] as const) {
      const v = sp.get(key);
      if (v) (out as any)[key] = v;
    }
    for (const key of ARRAY_KEYS) {
      const vals = sp.getAll(key);
      if (vals.length) (out as any)[key] = vals;
    }
    return out;
  }, [sp]);

  const write = useCallback(
    (next: Record<string, string | string[] | undefined>) => {
      const usp = new URLSearchParams(sp.toString());
      for (const [k, v] of Object.entries(next)) {
        usp.delete(k);
        if (v === undefined || v === "") continue;
        if (Array.isArray(v)) v.forEach((x) => usp.append(k, x));
        else usp.set(k, v);
      }
      router.replace(`${pathname}?${usp.toString()}`, { scroll: false });
    },
    [router, pathname, sp],
  );

  const toggleArray = useCallback(
    (key: string, value: string) => {
      const current = sp.getAll(key);
      const next = current.includes(value)
        ? current.filter((v) => v !== value)
        : [...current, value];
      write({ [key]: next });
    },
    [sp, write],
  );

  const setParam = useCallback((key: string, value?: string) => write({ [key]: value }), [write]);

  const clearAll = useCallback(() => {
    router.replace(pathname, { scroll: false });
  }, [router, pathname]);

  const activeCount = useMemo(() => {
    let n = 0;
    sp.forEach((_, k) => {
      if (k !== "sort" && k !== "order") n++;
    });
    return n;
  }, [sp]);

  return { params, write, toggleArray, setParam, clearAll, activeCount, sp };
}
