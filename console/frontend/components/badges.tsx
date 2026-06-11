"use client";

import { INTEGRITY_META, SEVERITY_META } from "@/lib/severity";
import type { Integrity, Outcome, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import { CheckCircle2, ShieldCheck, XCircle } from "lucide-react";
import { Badge, Tooltip } from "./ui";

export function SeverityBadge({ severity, withIcon = true }: { severity: Severity; withIcon?: boolean }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info;
  const Icon = meta.icon;
  return (
    <Badge className={cn(meta.bg, meta.text)}>
      {withIcon && <Icon className="h-3 w-3" />}
      {meta.label}
    </Badge>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info;
  return (
    <Tooltip content={meta.label}>
      <span className={cn("inline-block h-2 w-2 rounded-full", meta.dot)} aria-label={meta.label} />
    </Tooltip>
  );
}

export function IntegrityBadge({ value }: { value: Integrity }) {
  const meta = INTEGRITY_META[value] ?? INTEGRITY_META.unknown;
  return (
    <Tooltip content={meta.help}>
      <Badge className={cn("border-border bg-surface-2", meta.text)}>
        <ShieldCheck className="h-3 w-3" />
        {meta.label}
      </Badge>
    </Tooltip>
  );
}

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  if (outcome === "failure")
    return (
      <span className="inline-flex items-center gap-1 text-2xs text-bad-red">
        <XCircle className="h-3 w-3" /> denied
      </span>
    );
  if (outcome === "success")
    return (
      <span className="inline-flex items-center gap-1 text-2xs text-fg-subtle">
        <CheckCircle2 className="h-3 w-3" /> ok
      </span>
    );
  return <span className="text-2xs text-fg-subtle">—</span>;
}
