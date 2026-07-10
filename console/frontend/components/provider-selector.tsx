"use client";

import { listConnections } from "@/lib/api";
import { CONFIG_PROVIDERS_HREF } from "@/lib/routes";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Check, ChevronDown, Cloud } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

type ProviderSelectorProps = {
  platform: string;
  value: string;
  onChange: (connectionId: string) => void;
  className?: string;
  label?: string;
  /** Raise menu above wizard modals (z-[300]). */
  elevated?: boolean;
};

const GLASS_TRIGGER =
  "box-border flex h-9 min-w-[10rem] w-full items-center justify-between gap-2 rounded-md border border-white/10 bg-surface/80 px-3 text-left text-sm leading-none text-fg shadow-[0_1px_0_rgb(255_255_255/0.06)_inset] backdrop-blur transition-colors hover:bg-surface/90 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:cursor-not-allowed disabled:opacity-50";

const GLASS_MENU =
  "z-[200] min-w-[10rem] animate-fade-in overflow-hidden rounded-md border border-white/10 bg-surface/95 p-1 shadow-[0_12px_40px_-16px_rgb(0_0_0/0.75)] backdrop-blur";

export function ProviderSelector({
  platform,
  value,
  onChange,
  className,
  label = "Authentication",
  elevated = false,
}: ProviderSelectorProps) {
  const providers = useQuery({
    queryKey: ["config", "connections"],
    queryFn: listConnections,
    staleTime: 60_000,
  });

  const rows = (providers.data?.connections ?? []).filter(
    (c) => c.platform.toLowerCase() === platform.toLowerCase(),
  );
  const showLabel = Boolean(label);
  const [open, setOpen] = useState(false);
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLUListElement>(null);

  // Clear a stale connection id (wrong platform / deleted) — never auto-select a replacement.
  useEffect(() => {
    if (providers.isLoading || !providers.data) return;
    if (!value) return;
    const platformRows = providers.data.connections.filter(
      (c) => c.platform.toLowerCase() === platform.toLowerCase(),
    );
    if (!platformRows.some((c) => c.id === value)) onChange("");
    // onChange may be an inline callback; only re-run when selection or list changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional
  }, [providers.isLoading, providers.data, platform, value]);

  const updateMenuPos = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    setMenuPos({
      top: rect.bottom + 4,
      left: rect.left,
      width: Math.max(rect.width, 160),
    });
  }, []);

  useLayoutEffect(() => {
    if (!open) {
      setMenuPos(null);
      return;
    }
    updateMenuPos();
  }, [open, updateMenuPos]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const target = e.target as Node;
      if (triggerRef.current?.contains(target) || menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onReposition = () => updateMenuPos();
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", onReposition);
    window.addEventListener("scroll", onReposition, true);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", onReposition);
      window.removeEventListener("scroll", onReposition, true);
    };
  }, [open, updateMenuPos]);

  const selected = rows.find((c) => c.id === value);
  const isNone = !selected;
  const empty = !providers.isLoading && rows.length === 0;

  const pick = (connectionId: string) => {
    onChange(connectionId);
    setOpen(false);
  };

  const menu =
    open && menuPos && typeof document !== "undefined"
      ? createPortal(
          <ul
            ref={menuRef}
            role="listbox"
            className={cn(GLASS_MENU, elevated && "z-[400]")}
            style={{
              position: "fixed",
              top: menuPos.top,
              left: menuPos.left,
              width: menuPos.width,
            }}
          >
            <li role="option" aria-selected={isNone}>
              <button
                type="button"
                onClick={() => pick("")}
                className={cn(
                  "flex w-full items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-left text-sm transition-colors hover:bg-white/5",
                  isNone ? "text-fg" : "text-fg-subtle",
                )}
              >
                <span className="truncate">None</span>
                {isNone && <Check className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />}
              </button>
            </li>
            {rows.map((conn) => {
              const active = conn.id === value;
              return (
                <li key={conn.id} role="option" aria-selected={active}>
                  <button
                    type="button"
                    onClick={() => pick(conn.id)}
                    className={cn(
                      "flex w-full items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-left text-sm transition-colors hover:bg-white/5",
                      active ? "text-fg" : "text-fg-subtle",
                    )}
                  >
                    <span className="truncate">{conn.name}</span>
                    {active && <Check className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />}
                  </button>
                </li>
              );
            })}
          </ul>,
          document.body,
        )
      : null;

  return (
    <div className={className ?? (showLabel ? "block space-y-1.5" : "block")}>
      {showLabel && (
        <span className="flex items-center gap-1.5 text-sm font-medium text-fg">
          <Cloud className="h-3.5 w-3.5 text-accent" aria-hidden />
          {label}
        </span>
      )}
      <div className="relative">
        <button
          ref={triggerRef}
          type="button"
          disabled={providers.isLoading}
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-label={showLabel ? undefined : "Authentication"}
          onClick={() => setOpen((v) => !v)}
          className={GLASS_TRIGGER}
        >
          <span className={cn("min-w-0 truncate", isNone && "text-fg-subtle")}>
            {providers.isLoading ? "Loading…" : isNone ? "None" : selected.name}
          </span>
          <ChevronDown
            className={cn("h-3.5 w-3.5 shrink-0 opacity-60 transition-transform", open && "rotate-180")}
          />
        </button>
        {menu}
      </div>
      {empty && showLabel && (
        <p className="mt-1 text-xs text-fg-subtle">
          No named authentication for this platform.{" "}
          <Link href={CONFIG_PROVIDERS_HREF} className="text-accent hover:underline">
            Add one in Configuration → Authentication
          </Link>
          , or use None for ambient credentials.
        </p>
      )}
    </div>
  );
}
