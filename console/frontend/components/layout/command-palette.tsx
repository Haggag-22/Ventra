"use client";

import { useCase } from "@/components/case-context";
import { api } from "@/lib/api";
import { caseCloud } from "@/lib/cloud-sources";
import { panelLabel } from "@/lib/panel-labels";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  CornerDownLeft,
  Database,
  FileText,
  Fingerprint,
  Gauge,
  Globe,
  Globe2,
  Network,
  ScrollText,
  Search,
  ShieldAlert,
  User,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

interface Item {
  id: string;
  label: string;
  hint?: string;
  icon: typeof Gauge;
  run: () => void;
}

const PANELS = [
  { href: "timeline", panel: "timeline" as const, icon: Activity },
  { href: "cloudtrail", panel: "cloudtrail" as const, icon: ScrollText },
  { href: "search", panel: "search" as const, icon: ShieldAlert },
  { href: "identity", panel: "identity" as const, icon: Fingerprint },
  { href: "network", panel: "network" as const, icon: Network },
  { href: "web", panel: "web" as const, icon: Globe2 },
  { href: "data-access", panel: "data-access" as const, icon: Database },
  { href: "collection", panel: "collection" as const, icon: Gauge },
  { href: "report", panel: "report" as const, icon: FileText },
];

export function CommandPalette({
  caseId,
  open,
  onClose,
}: {
  caseId: string;
  open: boolean;
  onClose: () => void;
}) {
  const router = useRouter();
  const { summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const facets = useQuery({
    queryKey: ["facets", caseId, "palette"],
    queryFn: () => api.facets(caseId),
    enabled: open,
  });

  useEffect(() => {
    if (open) {
      setQ("");
      setCursor(0);
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [open]);

  const items: Item[] = useMemo(() => {
    const go = (path: string) => () => {
      router.push(`/cases/${caseId}/${path}`);
      onClose();
    };
    const base: Item[] = PANELS.map((p) => ({
      id: `panel-${p.href}`,
      label: panelLabel(cloud, p.panel),
      hint: "Panel",
      icon: p.icon,
      run: go(p.href),
    }));
    const principals = (facets.data?.user_name ?? []).slice(0, 6).map((f) => ({
      id: `user-${f.value}`,
      label: f.value,
      hint: `Principal · ${f.count} events`,
      icon: User,
      run: () => {
        router.push(`/cases/${caseId}/timeline?related_user=${encodeURIComponent(f.value)}`);
        onClose();
      },
    }));
    const ips = (facets.data?.source_ip ?? []).slice(0, 6).map((f) => ({
      id: `ip-${f.value}`,
      label: f.value,
      hint: `Source IP · ${f.count} events`,
      icon: Globe,
      run: () => {
        router.push(`/cases/${caseId}/timeline?related_ip=${encodeURIComponent(f.value)}`);
        onClose();
      },
    }));
    const all = [...base, ...principals, ...ips];
    if (!q.trim()) return all;
    const needle = q.toLowerCase();
    const filtered = all.filter((i) => i.label.toLowerCase().includes(needle));
    // Always offer a full-text search action.
    filtered.push({
      id: "search-action",
      label: `Search findings for “${q}”`,
      hint: "Full-text",
      icon: Search,
      run: () => {
        router.push(`/cases/${caseId}/search?q=${encodeURIComponent(q)}`);
        onClose();
      },
    });
    return filtered;
  }, [q, facets.data, caseId, router, onClose, cloud]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => Math.min(c + 1, items.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        items[cursor]?.run();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, items, cursor, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center bg-black/50 pt-[12vh] animate-fade-in"
      onMouseDown={onClose}
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 border-b border-border px-4">
          <Search className="h-4 w-4 text-fg-subtle" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setCursor(0);
            }}
            placeholder="Jump to a panel, principal, IP, or search events…"
            className="h-12 w-full bg-transparent text-sm text-fg placeholder:text-fg-subtle/70 focus:outline-none"
          />
        </div>
        <div className="max-h-[50vh] overflow-y-auto p-1.5">
          {items.map((item, i) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onMouseEnter={() => setCursor(i)}
                onClick={item.run}
                className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm ${
                  i === cursor ? "bg-accent/12 text-fg" : "text-fg-subtle hover:bg-surface-2"
                }`}
              >
                <Icon className="h-4 w-4 shrink-0 text-fg-subtle" />
                <span className="flex-1 truncate">{item.label}</span>
                {item.hint && <span className="text-2xs text-fg-subtle">{item.hint}</span>}
                {i === cursor && <CornerDownLeft className="h-3.5 w-3.5 text-fg-subtle" />}
              </button>
            );
          })}
          {items.length === 0 && (
            <div className="px-3 py-8 text-center text-sm text-fg-subtle">No matches.</div>
          )}
        </div>
      </div>
    </div>
  );
}
