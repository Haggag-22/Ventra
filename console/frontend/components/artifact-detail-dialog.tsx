"use client";

import { ArtifactIcon } from "@/components/artifact-icon";
import { ParamFieldInfo } from "@/components/param-field-info";
import { Button } from "@/components/ui";
import { api } from "@/lib/api";
import { resolvedParamFields } from "@/lib/artifact-params";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { acquirePermissionModel } from "@/lib/catalog";
import { gcpCollectorApiInfo } from "@/lib/gcp-collector-apis";
import { collectorSourceHint } from "@/lib/collector-source-hints";
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
  const paramFields = resolvedParamFields(art);
  const gcpApis = art.cloud.toLowerCase() === "gcp" ? gcpCollectorApiInfo(art.collector) : null;
  const sourceHint = collectorSourceHint(art.cloud, art.collector);
  const permissionLabel = `${acquirePermissionModel(art.cloud)} actions`;
  return (
    <div className="space-y-1">
      <Field label="Description">{art.description}</Field>
      {sourceHint ? <Field label="Collects from">{sourceHint}</Field> : null}
      {art.subset_of ? (
        <Field label="Included in">
          <span className="text-fg">{displayArtifactLabel(art.subset_of)}</span>
          <span className="mt-0.5 block text-xs text-fg-subtle">
            A filtered view of {displayArtifactLabel(art.subset_of)}. Selecting it too adds no extra
            coverage — it only produces a smaller, pre-filtered file.
          </span>
        </Field>
      ) : null}
      {gcpApis?.calls.length ? (
        <Field label="API">
          <ul className="space-y-0.5 text-xs text-fg-subtle">
            {gcpApis.calls.map((api) => (
              <li key={api}>{api}</li>
            ))}
          </ul>
        </Field>
      ) : null}
      {gcpApis?.logSource?.length ? (
        <Field label="Log Source">
          <ul className="space-y-0.5 text-xs text-fg-subtle">
            {gcpApis.logSource.map((src) => (
              <li key={src} className="mono">
                {src}
              </li>
            ))}
          </ul>
        </Field>
      ) : null}
      {art.required_actions?.length ? (
        <Field label={permissionLabel}>
          <ul className="max-h-40 space-y-0.5 overflow-auto text-2xs">
            {art.required_actions.map((a) => (
              <li key={a} className="mono text-fg-subtle">
                {a}
              </li>
            ))}
          </ul>
        </Field>
      ) : null}
      {paramFields.length ? (
        <Field label="Parameters">
          <ul className="space-y-2 text-xs">
            {paramFields.map((field) => (
              <li key={field.key}>
                <div className="flex items-center gap-1">
                  <span className="mono">
                    {field.label}
                    {field.required ? " · required" : ""}
                  </span>
                  <ParamFieldInfo
                    label={field.label}
                    description={field.description}
                    docUrl={field.docUrl}
                    className="h-4 w-4"
                    iconClassName="h-3 w-3"
                  />
                </div>
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
          <h3 className="flex flex-wrap items-center gap-2 text-sm font-semibold">
            <ArtifactIcon cloud={cloud} collector={collector} size={22} />
            <span>{displayArtifactLabel(collector, cloud)}</span>
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
