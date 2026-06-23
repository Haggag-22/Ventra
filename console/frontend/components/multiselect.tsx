"use client";

import { cn } from "@/lib/utils";
import { fmtNum } from "@/lib/format";
import { Check, ChevronDown, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export interface Option {
  value: string;
  label?: string;
  count?: number;
}

/**
 * Toolbar multi-select dropdown (Event Names / Sources / Regions). A bordered trigger button
 * with a selection-count badge; the panel has a search box and checkbox rows.
 */
export function MultiSelect({
  label,
  icon: Icon,
  options,
  selected,
  onToggle,
  onClear,
  searchable = true,
  align = "left",
  variant = "default",
  lockedValues,
}: {
  label: string;
  icon?: LucideIcon;
  options: Option[];
  selected: string[];
  onToggle: (value: string) => void;
  onClear: () => void;
  searchable?: boolean;
  align?: "left" | "right";
  variant?: "default" | "cloudtrail";
  lockedValues?: string[];
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const shown = q
    ? options.filter((o) => o.value.toLowerCase().includes(q.toLowerCase()))
    : options;

  const ct = variant === "cloudtrail";

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          ct
            ? cn(
                "ct-btn",
                selected.length > 0 && "ct-btn-active",
              )
            : cn(
                "flex h-9 items-center gap-2 rounded-md border bg-surface-2 px-3 text-xs transition-colors",
                selected.length > 0
                  ? "border-accent/40 text-fg"
                  : "border-border text-fg-subtle hover:text-fg",
              ),
        )}
      >
        {Icon && <Icon className="h-3.5 w-3.5" />}
        {label}
        {selected.length > 0 && (
          <span
            className={cn(
              "mono rounded-full px-1.5 text-2xs bg-accent/15 text-accent",
            )}
          >
            {selected.length}
          </span>
        )}
        <ChevronDown className="h-3.5 w-3.5 opacity-60" />
      </button>

      {open && (
        <div
          className={cn(
            "absolute top-full z-50 mt-1 w-64 animate-fade-in rounded-lg border border-border bg-surface shadow-pop",
            align === "right" ? "right-0" : "left-0",
          )}
        >
          {searchable && (
            <div className={cn("border-b p-2", "border-border")}>
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder={`Filter ${label.toLowerCase()}…`}
                className={cn(
                  "h-7 w-full rounded-md border px-2 text-xs focus:outline-none",
                  ct
                    ? "border-border bg-surface-2 text-fg placeholder:text-fg-subtle/60 focus:border-accent/50"
                    : "border-border bg-surface text-fg placeholder:text-fg-subtle/60 focus:border-accent/50",
                )}
                autoFocus
              />
            </div>
          )}
          <div className="max-h-64 overflow-y-auto p-1">
            {shown.length === 0 && (
              <div className={cn("px-2 py-3 text-center text-2xs text-fg-subtle")}>
                No options.
              </div>
            )}
            {shown.map((o) => {
              const on = selected.includes(o.value);
              const locked = lockedValues?.includes(o.value);
              return (
                <button
                  key={o.value}
                  onClick={() => !locked && onToggle(o.value)}
                  disabled={locked}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs hover:bg-surface-2",
                    locked && "cursor-not-allowed opacity-60",
                  )}
                >
                  <span
                    className={cn(
                      "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded border",
                      on
                        ? "border-accent bg-accent text-accent-fg"
                        : "border-border",
                    )}
                  >
                    {on && <Check className="h-2.5 w-2.5" />}
                  </span>
                  <span className="mono flex-1 truncate text-fg">
                    {o.label ?? o.value}
                  </span>
                  {o.count !== undefined && (
                    <span className="mono text-2xs text-fg-subtle">
                      {fmtNum(o.count)}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
          {selected.length > 0 && (
            <div className="border-t border-border p-1">
              <button
                onClick={onClear}
                className="w-full rounded-md px-2 py-1.5 text-left text-2xs text-fg-subtle hover:bg-surface-2 hover:text-fg"
              >
                Clear {selected.length} selected
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Single-select dropdown for sort field / order. */
export function SelectDropdown({
  value,
  options,
  onChange,
  icon: Icon,
  displayLabel,
  variant = "default",
  align = "right",
  className,
  menuClassName,
}: {
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  icon?: LucideIcon;
  displayLabel?: string;
  variant?: "default" | "cloudtrail";
  align?: "left" | "right";
  className?: string;
  menuClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);
  const current = options.find((o) => o.value === value);
  const ct = variant === "cloudtrail";
  const shown = displayLabel ?? current?.label ?? value;

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          ct
            ? "ct-btn"
            : "flex h-9 items-center gap-2 rounded-md border border-border bg-surface-2 px-3 text-xs text-fg-subtle hover:text-fg",
          className,
        )}
      >
        {Icon && <Icon className="h-3.5 w-3.5" />}
        <span className={ct ? "" : "text-fg"}>{shown}</span>
        <ChevronDown className="h-3.5 w-3.5 opacity-60" />
      </button>
      {open && (
        <div
          className={cn(
            "absolute top-full z-50 mt-1 w-40 animate-fade-in rounded-lg border border-border bg-surface p-1 shadow-pop",
            align === "right" ? "right-0" : "left-0",
            menuClassName,
          )}
        >
          {options.map((o) => (
            <button
              key={o.value}
              onClick={() => {
                onChange(o.value);
                setOpen(false);
              }}
              className={cn(
                "flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-xs hover:bg-surface-2",
                o.value === value ? "text-accent" : "text-fg-subtle",
              )}
            >
              {o.label}
              {o.value === value && <Check className="h-3 w-3" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
