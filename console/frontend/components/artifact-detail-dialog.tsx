"use client";

import { ArtifactIcon } from "@/components/artifact-icon";
import { Button } from "@/components/ui";
import { api } from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import type { Artifact } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Info, Loader2, X } from "lucide-react";
import { useState } from "react";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 border-b border-border/50 py-2 last:border-0">
      <div className="text-2xs uppercase tracking-wide text-fg-subtle">{label}</div>
      <div className="min-w-0 text-sm text-fg">{children}</div>
    </div>
  );
}

function ArtifactBody({ art }: { art: Artifact }) {
  const paramKeys = Object.keys(art.parameters ?? {});
  return (
    <div className="space-y-1">
      <Field label="Name">
        <span className="mono text-xs">{art.name}</span>
      </Field>
      <Field label="Collector">
        <span className="mono text-xs">{art.collector}</span>
      </Field>
      <Field label="Version">{art.version}</Field>
      <Field label="Category">{art.category}</Field>
      <Field label="Volume">{art.estimated_volume}</Field>
      <Field label="Description">{art.description}</Field>
      {art.aliases?.length ? (
        <Field label="Aliases">
          <span className="mono text-xs">{art.aliases.join(", ")}</span>
        </Field>
      ) : null}
      {art.sources?.length ? (
        <Field label="Sources">
          <ul className="space-y-1 text-xs">
            {art.sources.map((s, i) => (
              <li key={i} className="mono">
                {s.type}
                {s.format ? ` (${s.format})` : ""}
              </li>
            ))}
          </ul>
        </Field>
      ) : null}
      {paramKeys.length ? (
        <Field label="Parameters">
          <ul className="space-y-1 text-xs">
            {paramKeys.map((key) => {
              const p = (art.parameters as Record<string, { type?: string; required?: boolean }>)[
                key
              ];
              return (
                <li key={key} className="mono">
                  {key}
                  {p?.type ? ` · ${p.type}` : ""}
                  {p?.required ? " · required" : ""}
                </li>
              );
            })}
          </ul>
        </Field>
      ) : null}
      {art.required_actions?.length ? (
        <Field label="IAM actions">
          <ul className="max-h-40 space-y-0.5 overflow-auto text-2xs">
            {art.required_actions.map((a) => (
              <li key={a} className="mono text-fg-subtle">
                {a}
              </li>
            ))}
          </ul>
        </Field>
      ) : null}
    </div>
  );
}

export function ArtifactDetailDialog({
  collector,
  cloud,
  open,
  onClose,
}: {
  collector: string | null;
  cloud: string;
  open: boolean;
  onClose: () => void;
}) {
  const detail = useQuery({
    queryKey: ["artifact", cloud, collector],
    queryFn: () => api.artifact(collector!, cloud),
    enabled: open && !!collector,
  });

  if (!open || !collector) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4 animate-fade-in"
      onMouseDown={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <ArtifactIcon cloud={cloud} collector={collector} size={22} />
            <span>{displayArtifactLabel(collector)}</span>
          </h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-y-auto px-4 py-3">
          {detail.isLoading ? (
            <div className="flex items-center justify-center gap-2 py-10 text-sm text-fg-subtle">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading artifact…
            </div>
          ) : detail.error ? (
            <p className="py-6 text-center text-sm text-bad-red">
              {(detail.error as Error).message || "Failed to load artifact"}
            </p>
          ) : detail.data ? (
            <ArtifactBody art={detail.data} />
          ) : null}
        </div>

        <div className="border-t border-border px-4 py-3">
          <Button variant="secondary" className="w-full justify-center" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

/** Small info button that opens the artifact detail dialog. */
export function ArtifactInfoButton({
  collector,
  cloud,
  className,
}: {
  collector: string;
  cloud: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
        className={cn(
          "inline-flex h-6 w-6 shrink-0 items-center justify-center rounded text-fg-subtle hover:bg-surface-2 hover:text-fg",
          className,
        )}
        aria-label={`Details for ${collector}`}
      >
        <Info className="h-3.5 w-3.5" />
      </button>
      <ArtifactDetailDialog
        collector={collector}
        cloud={cloud}
        open={open}
        onClose={() => setOpen(false)}
      />
    </>
  );
}
