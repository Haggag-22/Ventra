"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { cn } from "@/lib/utils";
import type { CasePlatform } from "@/lib/catalog";
import { Check, Lock } from "lucide-react";
import { PROVIDER_META, PROVIDER_ORDER } from "./provider-meta";
import { PROVIDER_PLATFORMS, type ProviderPlatform } from "./types";

const COMING_SOON = new Set(
  PROVIDER_PLATFORMS.filter((p) => "comingSoon" in p && p.comingSoon).map((p) => p.id),
);

export function ProviderStepLink({
  platform,
  onSelect,
}: {
  platform: ProviderPlatform | "";
  onSelect: (platform: ProviderPlatform) => void;
}) {
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-base font-semibold text-fg">Choose a cloud platform</h2>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        {PROVIDER_ORDER.map((id) => {
          const meta = PROVIDER_META[id];
          const selected = platform === id;
          const disabled = COMING_SOON.has(id);
          return (
            <button
              key={id}
              type="button"
              disabled={disabled}
              aria-pressed={selected}
              onClick={() => onSelect(id)}
              className={cn(
                "group relative flex items-center gap-3.5 rounded-xl border p-4 text-left",
                "transition-[transform,border-color,background-color,box-shadow] duration-150",
                "focus-visible:outline-none",
                disabled
                  ? "cursor-not-allowed border-border bg-surface/40 opacity-60"
                  : selected
                    ? "border-ok-green/35 bg-ok-green/[0.06] shadow-[0_0_0_1px_rgb(var(--ok-green)/0.2),0_10px_30px_-18px_rgb(0_0_0/0.5)]"
                    : "border-border bg-surface hover:-translate-y-0.5 hover:border-border-strong hover:bg-surface-2",
              )}
            >
              <span
                className={cn(
                  "flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border transition-colors",
                  selected
                    ? "border-ok-green/30 bg-bg"
                    : "border-border bg-bg/60 group-hover:border-border-strong",
                )}
              >
                <CloudProviderIcon cloud={id as CasePlatform} />
              </span>

              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-sm font-semibold leading-tight text-fg">{meta.label}</span>
                  {disabled && (
                    <span className="inline-flex items-center gap-1 rounded-full border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-fg-faint">
                      <Lock className="h-2.5 w-2.5" />
                      Soon
                    </span>
                  )}
                </span>
              </span>

              <span
                className={cn(
                  "flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-all",
                  selected
                    ? "scale-100 border-ok-green bg-ok-green text-white"
                    : "scale-90 border-border bg-surface text-transparent group-hover:border-border-strong",
                )}
              >
                <Check className="h-3 w-3" strokeWidth={3} />
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
