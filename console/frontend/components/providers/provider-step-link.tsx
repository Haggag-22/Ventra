"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Input } from "@/components/ui";
import { cn } from "@/lib/utils";
import type { CasePlatform } from "@/lib/catalog";
import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { PROVIDER_PLATFORMS, type ProviderPlatform } from "./types";

export function ProviderStepLink({
  platform,
  onSelect,
}: {
  platform: ProviderPlatform | "";
  onSelect: (platform: ProviderPlatform) => void;
}) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const filtered = useMemo(() => {
    if (!q) return PROVIDER_PLATFORMS;
    return PROVIDER_PLATFORMS.filter(
      (p) =>
        p.label.toLowerCase().includes(q) ||
        p.id.includes(q) ||
        p.searchable.includes(q),
    );
  }, [q]);

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Link a provider</h2>
        <p className="mt-1 text-sm text-fg-subtle">
          Select the cloud platform you want Ventra to collect from. Credentials are configured on
          the Ventra server host — nothing sensitive is stored in the browser.
        </p>
      </div>

      <div className="relative max-w-md">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search providers…"
          className="pl-9"
        />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {filtered.map((p) => {
          const selected = platform === p.id;
          const disabled = "comingSoon" in p && p.comingSoon;
          return (
            <button
              key={p.id}
              type="button"
              disabled={disabled}
              onClick={() => onSelect(p.id)}
              className={cn(
                "flex items-start gap-3 rounded-lg border p-4 text-left transition-colors",
                disabled && "cursor-not-allowed opacity-60",
                selected
                  ? "border-accent/60 bg-accent/10 ring-1 ring-accent/30"
                  : "border-border bg-surface hover:border-border-strong hover:bg-surface-2",
              )}
            >
              <span
                className={cn(
                  "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border",
                  selected ? "border-accent bg-accent" : "border-border bg-surface",
                )}
              >
                {selected && <span className="h-1.5 w-1.5 rounded-full bg-accent-fg" />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-2">
                  <CloudProviderIcon cloud={p.id as CasePlatform} />
                  <span className="text-sm font-medium text-fg">{p.label}</span>
                </span>
                {disabled && (
                  <span className="mt-1 inline-block text-xs text-fg-subtle">Coming soon</span>
                )}
              </span>
            </button>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <p className="text-sm text-fg-subtle">No providers match your search.</p>
      )}
    </div>
  );
}
