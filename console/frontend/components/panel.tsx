"use client";

import { PanelCollectors } from "@/components/panel-collectors";
import type { PanelId } from "@/lib/panel-collectors";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

export function PanelHeader({
  icon: Icon,
  title,
  description,
  panel,
  actions,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  panel?: PanelId;
  actions?: React.ReactNode;
}) {
  const stacked = Boolean(panel || description);

  return (
    <div className="flex items-start justify-between gap-4 border-b border-border bg-surface px-6 py-3.5">
      <div
        className={cn(
          "flex min-w-0 flex-1 gap-3",
          stacked ? "items-start" : "items-center",
        )}
      >
        <div
          className={cn(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-2 text-accent",
            stacked && "mt-0.5",
          )}
        >
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <h1 className="text-base font-semibold tracking-tight leading-none">{title}</h1>
          {description && <p className="mt-0.5 text-xs text-fg-subtle">{description}</p>}
          {panel && <PanelCollectors panel={panel} />}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function PanelBody({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("p-6", className)}>{children}</div>;
}
