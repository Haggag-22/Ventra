"use client";

import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";
import { Card } from "./ui";

export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "default",
  onClick,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon?: LucideIcon;
  tone?: "default" | "critical" | "high" | "accent";
  onClick?: () => void;
}) {
  const toneText =
    tone === "critical"
      ? "text-critical"
      : tone === "high"
        ? "text-high"
        : tone === "accent"
          ? "text-accent"
          : "text-fg";
  return (
    <Card
      className={cn("p-4", onClick && "cursor-pointer hover:border-accent/40 transition-colors")}
      onClick={onClick}
    >
      <div className="flex items-center justify-between">
        <span className="stat-label">{label}</span>
        {Icon && <Icon className="h-4 w-4 text-fg-subtle" />}
      </div>
      <div className={cn("mt-2 text-2xl font-semibold tabular-nums", toneText)}>{value}</div>
      {sub && <div className="mt-1 text-xs text-fg-subtle">{sub}</div>}
    </Card>
  );
}
