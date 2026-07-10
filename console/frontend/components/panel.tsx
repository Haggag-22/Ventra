"use client";

import { PanelCollectors } from "@/components/panel-collectors";
import type { PanelId } from "@/lib/panel-collectors";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

export function PanelHeader({
  icon: Icon,
  title,
  panel,
  actions,
}: {
  icon: LucideIcon;
  title: string;
  panel?: PanelId;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border/80 bg-surface/60 px-6 py-5 backdrop-blur-sm">
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-surface-2 text-accent">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <h1 className="page-title">{title}</h1>
          {panel && <PanelCollectors panel={panel} />}
        </div>
      </div>
      {actions && (
        <div className="flex shrink-0 items-center gap-2">{actions}</div>
      )}
    </div>
  );
}

export function PanelBody({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("p-6", className)}>{children}</div>;
}
