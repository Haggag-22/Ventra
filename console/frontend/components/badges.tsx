"use client";

import { artifactSeverityLabel, artifactSeverityMeta } from "@/lib/artifact-severity";
import { INTEGRITY_META, SEVERITY_META } from "@/lib/severity";
import type { Integrity, Outcome, RunStatus, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import { CheckCircle2, ShieldCheck, XCircle } from "lucide-react";
import { Badge, Tooltip } from "./ui";

/** Tone classes for collection/run status pills. */
export function runStatusTone(status: RunStatus): string {
  if (status === "completed") return "text-ok-green bg-ok-green/10 border-ok-green/30";
  if (status === "failed") return "text-bad-red bg-bad-red/10 border-bad-red/30";
  if (status === "cancelled") return "text-fg-subtle bg-surface-2 border-border";
  if (status === "cancelling") return "text-warn-amber bg-warn-amber/10 border-warn-amber/30";
  if (status === "running" || status === "pending")
    return "text-accent-cta bg-accent-cta/10 border-accent-cta/30";
  return "text-fg-subtle bg-surface-2 border-border";
}

export function RunStatusBadge({
  status,
  className,
}: {
  status: RunStatus;
  className?: string;
}) {
  return (
    <Badge className={cn("table-badge capitalize", runStatusTone(status), className)}>
      {status}
    </Badge>
  );
}

export function ArtifactSeverityBadge({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  const label = artifactSeverityLabel(severity);
  if (!label) return null;
  const meta = artifactSeverityMeta(severity);
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-2xs font-medium",
        meta?.className ?? "border-border bg-surface-2 text-fg-subtle",
        className,
      )}
    >
      {label}
    </span>
  );
}

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

export function IntegrityBadge({
  value,
  showLabel = true,
}: {
  value: Integrity;
  showLabel?: boolean;
}) {
  const meta = INTEGRITY_META[value] ?? INTEGRITY_META.unknown;
  return (
    <Tooltip content={meta.help}>
      <Badge className={cn("border-border bg-surface-2", meta.text)}>
        <ShieldCheck className="h-3 w-3" />
        {showLabel && meta.label}
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
