"use client";

import { cn } from "@/lib/utils";
import {
  Activity,
  Copy,
  Fingerprint,
  Network,
  ScrollText,
  ShieldAlert,
  Waypoints,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useCase } from "./case-context";

type EntityKind = "ip" | "user" | "resource";

const PARAM: Record<EntityKind, string> = {
  ip: "related_ip",
  user: "related_user",
  resource: "related_resource",
};

// Where you can pivot to, and what each destination is good for.
const TARGETS = [
  { href: "timeline", label: "Timeline", icon: Activity },
  { href: "cloudtrail", label: "CloudTrail", icon: ScrollText },
  { href: "search", label: "Security Findings", icon: ShieldAlert },
  { href: "identity", label: "Identity & Access", icon: Fingerprint },
  { href: "network", label: "Network Activity", icon: Network },
];

/**
 * Wrap any IP / principal / ARN to make it a pivot anchor. Clicking opens a menu that jumps
 * to that entity's slice in every panel — the feature that makes Harbor an investigation
 * tool rather than a log viewer.
 */
export function Entity({
  kind,
  value,
  className,
  mono = true,
  truncate,
  excludeTargets,
}: {
  kind: EntityKind;
  value: string;
  className?: string;
  mono?: boolean;
  truncate?: boolean;
  excludeTargets?: string[];
}) {
  const { caseId } = useCase();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const targets = excludeTargets?.length
    ? TARGETS.filter((t) => !excludeTargets.includes(t.href))
    : TARGETS;

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  if (!value) return <span className="text-fg-subtle">—</span>;
  const param = PARAM[kind];

  return (
    <span ref={ref} className="relative inline-flex">
      <button
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className={cn(
          "inline-flex max-w-full items-center gap-1 rounded px-1 -mx-1 text-left hover:bg-accent/10 hover:text-accent transition-colors",
          mono && "mono text-xs",
          truncate && "truncate",
          className,
        )}
        title={value}
      >
        <Waypoints className="h-3 w-3 shrink-0 opacity-40" />
        <span className={cn(truncate && "truncate")}>{value}</span>
      </button>

      {open && (
        <div className="absolute left-0 top-full z-50 mt-1 w-56 animate-fade-in rounded-lg border border-border bg-surface-2 p-1 shadow-pop">
          <div className="px-2 py-1.5 text-2xs uppercase tracking-wide text-fg-subtle">
            Pivot on {kind}
          </div>
          <div className="mono truncate px-2 pb-1.5 text-2xs text-fg">{value}</div>
          <div className="my-1 h-px bg-border" />
          {targets.map((t) => {
            const Icon = t.icon;
            return (
              <Link
                key={t.href}
                href={`/cases/${caseId}/${t.href}?${param}=${encodeURIComponent(value)}`}
                onClick={() => setOpen(false)}
                className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg-subtle hover:bg-surface hover:text-fg"
              >
                <Icon className="h-3.5 w-3.5" />
                Show in {t.label}
              </Link>
            );
          })}
          <div className="my-1 h-px bg-border" />
          <button
            onClick={() => {
              navigator.clipboard?.writeText(value);
              setOpen(false);
            }}
            className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg-subtle hover:bg-surface hover:text-fg"
          >
            <Copy className="h-3.5 w-3.5" />
            Copy value
          </button>
        </div>
      )}
    </span>
  );
}
