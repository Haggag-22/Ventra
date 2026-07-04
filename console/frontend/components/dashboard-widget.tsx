"use client";

import { Card, CardHeader, EmptyState } from "@/components/ui";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

export function DashboardWidget({
  title,
  icon,
  href,
  viewAllLabel = "View all",
  emptyIcon,
  emptyTitle,
  emptyDescription,
  className,
  children,
}: {
  title: string;
  icon?: LucideIcon;
  href?: string;
  viewAllLabel?: string;
  emptyIcon?: LucideIcon;
  emptyTitle?: string;
  emptyDescription?: string;
  className?: string;
  children: ReactNode;
}) {
  const isEmpty =
    emptyTitle &&
    (children === null ||
      children === undefined ||
      (Array.isArray(children) && children.length === 0));

  return (
    <Card className={cn("glass-card-glow flex h-full flex-col overflow-hidden", className)}>
      <CardHeader
        title={title}
        icon={icon}
        action={
          href ? (
            <Link href={href} className="text-xs text-accent hover:underline">
              {viewAllLabel}
            </Link>
          ) : undefined
        }
      />
      <div className="flex flex-1 flex-col p-4">
        {isEmpty && emptyIcon && emptyTitle ? (
          <EmptyState icon={emptyIcon} title={emptyTitle} description={emptyDescription} />
        ) : (
          children
        )}
      </div>
    </Card>
  );
}
