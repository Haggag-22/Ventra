"use client";

import { cn } from "@/lib/utils";
import { ChevronRight } from "lucide-react";
import Link from "next/link";
import type { BreadcrumbItem } from "@/lib/routes";

export function Breadcrumbs({ items }: { items: BreadcrumbItem[] }) {
  if (!items.length) return null;
  return (
    <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
      {items.map((item, i) => {
        const last = i === items.length - 1;
        return (
          <span key={`${item.label}-${i}`} className="flex min-w-0 items-center gap-1">
            {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 text-fg-faint/80" aria-hidden />}
            {item.href && !last ? (
              <Link
                href={item.href}
                className="truncate text-fg-subtle transition-colors hover:text-accent"
              >
                {item.label}
              </Link>
            ) : (
              <span className={cn("truncate", last ? "font-medium text-fg" : "text-fg-subtle")}>
                {item.label}
              </span>
            )}
          </span>
        );
      })}
    </nav>
  );
}
