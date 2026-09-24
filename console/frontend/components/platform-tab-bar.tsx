"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { CASE_PLATFORM_LABELS, CASE_PLATFORMS, type CasePlatform } from "@/lib/catalog";
import { cn } from "@/lib/utils";

export type PlatformTab = "all" | CasePlatform;

export const PLATFORM_TABS: { id: PlatformTab; label: string }[] = [
  { id: "all", label: "All" },
  ...CASE_PLATFORMS.map((c) => ({ id: c as PlatformTab, label: CASE_PLATFORM_LABELS[c] })),
];

type PlatformTabBarProps = {
  value: PlatformTab;
  onChange: (tab: PlatformTab) => void;
  countFor: (tab: PlatformTab) => number;
  className?: string;
};

/** All / AWS / Azure / GCP (etc.) filter bar — matches Cases list styling. */
export function PlatformTabBar({ value, onChange, countFor, className }: PlatformTabBarProps) {
  return (
    <div className={cn("mb-5 flex items-center gap-1 border-b border-border/80", className)}>
      {PLATFORM_TABS.map((t) => {
        const active = value === t.id;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            className={cn(
              "relative -mb-px flex h-10 items-center gap-2 whitespace-nowrap px-3 text-sm font-medium transition-colors",
              active ? "text-fg" : "text-fg-subtle hover:text-fg",
            )}
          >
            {t.id !== "all" && <CloudProviderIcon cloud={t.id} />}
            {t.label}
            <span
              className={cn(
                "mono rounded-full px-1.5 py-0.5 text-2xs",
                active ? "bg-accent/15 text-accent" : "bg-surface text-fg-subtle",
              )}
            >
              {countFor(t.id)}
            </span>
            {active && <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-accent" />}
          </button>
        );
      })}
    </div>
  );
}

export function filterByPlatformTab<T>(
  items: T[],
  tab: PlatformTab,
  platformOf: (item: T) => string,
): T[] {
  if (tab === "all") return items;
  return items.filter((item) => platformOf(item) === tab);
}

export function countByPlatformTab<T>(
  items: T[],
  tab: PlatformTab,
  platformOf: (item: T) => string,
): number {
  return filterByPlatformTab(items, tab, platformOf).length;
}
