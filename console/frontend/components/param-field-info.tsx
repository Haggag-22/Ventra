"use client";

import { Popover } from "@/components/ui";
import { cn } from "@/lib/utils";
import { CircleHelp, ExternalLink } from "lucide-react";

export function ParamFieldInfo({
  label,
  description,
  docUrl,
  className,
  iconClassName,
}: {
  label: string;
  description?: string;
  docUrl?: string;
  className?: string;
  iconClassName?: string;
}) {
  if (!description && !docUrl) return null;

  return (
    <Popover
      align="start"
      side="top"
      trigger={
        <button
          type="button"
          aria-label={`About ${label}`}
          className={cn(
            "inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-fg-subtle hover:bg-surface-2 hover:text-fg",
            className,
          )}
        >
          <CircleHelp className={cn("h-3.5 w-3.5", iconClassName)} />
        </button>
      }
    >
      {description ? (
        <p className="break-words leading-snug text-fg">{description}</p>
      ) : null}
      {docUrl ? (
        <a
          href={docUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-1.5 inline-flex items-center gap-1 text-accent hover:underline"
          onClick={(event) => event.stopPropagation()}
        >
          Learn more
          <ExternalLink className="h-3 w-3" />
        </a>
      ) : null}
    </Popover>
  );
}

export function ParamFieldLabel({
  label,
  required,
  description,
  docUrl,
  compact,
}: {
  label: string;
  required?: boolean;
  description?: string;
  docUrl?: string;
  compact?: boolean;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className={cn("font-medium text-fg", compact ? "text-xs" : "text-sm")}>
        {label}
        {required ? <span className="ml-1 text-warn-amber">*</span> : null}
      </span>
      <ParamFieldInfo label={label} description={description} docUrl={docUrl} />
    </div>
  );
}
