"use client";

import { ArtifactIcon } from "@/components/artifact-icon";
import { useCase } from "@/components/case-context";
import { api } from "@/lib/api";
import type { Cloud } from "@/lib/catalog";
import {
  aggregateManifestSources,
  collectorStatusLabel,
  IMPLEMENTED_LOG_COLLECTORS,
  panelCollectorLabel,
  plannedCollectorDetail,
  resolvePanelCollectorCoverage,
  type CoverageState,
  type ManifestGap,
} from "@/lib/collection-coverage";
import {
  catalogItem,
  COLLECTOR_ASPECT_GROUPS,
  panelCollectors,
  type PanelCollectorRef,
  type PanelId,
} from "@/lib/panel-collectors";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Check, Minus } from "lucide-react";

type CollectorTint = "ok" | "partial" | "bad";

type CollectorSegment =
  | { kind: "single"; ref: PanelCollectorRef }
  | { kind: "aspect-group"; group: string; refs: PanelCollectorRef[] };

function aspectGroupKey(ref: PanelCollectorRef): string | null {
  if (ref.aspectGroup) return ref.aspectGroup;
  if (ref.id === "cloudtrail" && ref.cloudtrailAspect) return "cloudtrail";
  return null;
}

function aspectRowKey(ref: PanelCollectorRef): string {
  return ref.cloudtrailAspect ?? ref.id;
}

interface ResolvedRow {
  ref: PanelCollectorRef;
  label: string;
  tint: CollectorTint;
  statusLabel: string;
  title: string;
}

function displayCoverageState(id: string, state: CoverageState): CoverageState {
  if ((state === "not_run" || state === "planned") && !IMPLEMENTED_LOG_COLLECTORS.has(id)) {
    return "planned";
  }
  return state;
}

function resolveCollectorTint(state: CoverageState, records: number): CollectorTint {
  if (state === "collected" && records > 0) return "ok";
  if (state === "partial" && records > 0) return "partial";
  return "bad";
}

function segmentCollectors(refs: PanelCollectorRef[]): CollectorSegment[] {
  const out: CollectorSegment[] = [];
  let batch: PanelCollectorRef[] = [];
  let batchGroup: string | null = null;

  const flush = () => {
    if (batch.length === 0) return;
    if (batch.length === 1) out.push({ kind: "single", ref: batch[0] });
    else out.push({ kind: "aspect-group", group: batchGroup!, refs: batch });
    batch = [];
    batchGroup = null;
  };

  for (const ref of refs) {
    const group = aspectGroupKey(ref);
    if (group) {
      if (batchGroup && batchGroup !== group) flush();
      batchGroup = group;
      batch.push(ref);
    } else {
      flush();
      out.push({ kind: "single", ref });
    }
  }
  flush();
  return out;
}

function CollectorCheckbox({ tint }: { tint: CollectorTint }) {
  return (
    <span
      className={cn(
        "panel-collector-checkbox",
        tint === "ok" && "is-ok",
        tint === "partial" && "is-partial",
        tint === "bad" && "is-bad",
      )}
      aria-hidden
    >
      {tint === "ok" && <Check className="h-3 w-3" strokeWidth={2.5} />}
      {tint === "partial" && <Minus className="h-3 w-3" strokeWidth={2.5} />}
    </span>
  );
}

function resolveRow(
  ref: PanelCollectorRef,
  cloud: Cloud,
  bySource: Map<string, { status: string; records: number; notes: string }> | null,
  manifestGaps: ManifestGap[],
  collected: Set<string>,
  gapByName: Map<string, { detail?: string }>,
): ResolvedRow {
  const item = catalogItem(cloud, ref.id);
  const label = panelCollectorLabel(ref, item?.label);

  if (bySource) {
    const resolved = resolvePanelCollectorCoverage(ref, bySource, manifestGaps);
    const display = displayCoverageState(ref.id, resolved.state);
    const tint = resolveCollectorTint(resolved.state, resolved.records);
    const statusLabel = collectorStatusLabel(display);
    const detail =
      resolved.state === "partial" && resolved.gaps.length
        ? resolved.gaps.map((g) => g.detail).join(" ")
        : display === "planned"
          ? plannedCollectorDetail(resolved.detail)
          : resolved.detail;
    return {
      ref,
      label,
      tint,
      statusLabel,
      title: [statusLabel, ref.note, detail].filter(Boolean).join(" · "),
    };
  }

  const checked = collected.has(ref.id);
  const gap = gapByName.get(ref.id);
  const tint: CollectorTint = checked ? "ok" : "bad";
  const statusLabel = checked
    ? "Collected"
    : gap
      ? collectorStatusLabel("not_enabled")
      : "Not run";
  const detail = checked
    ? item?.description ?? "Collected in this case"
    : gap?.detail ?? "Collector did not run for this case.";

  return {
    ref,
    label,
    tint,
    statusLabel,
    title: [statusLabel, ref.note, detail].filter(Boolean).join(" · "),
  };
}

function CollectorCard({ row, cloud }: { row: ResolvedRow; cloud: Cloud }) {
  return (
    <div
      className={cn(
        "panel-collector-card",
        row.tint === "ok" && "is-ok",
        row.tint === "partial" && "is-partial",
        row.tint === "bad" && "is-bad",
      )}
      title={row.title}
      aria-label={`${row.label}: ${row.statusLabel}`}
    >
      <ArtifactIcon cloud={cloud} collector={row.ref.id} size={22} className="panel-collector-icon" />
      <span className="panel-collector-name">{row.label}</span>
      <CollectorCheckbox tint={row.tint} />
    </div>
  );
}

function CollectorAspectGroup({
  group,
  refs,
  cloud,
  bySource,
  manifestGaps,
  collected,
  gapByName,
}: {
  group: string;
  refs: PanelCollectorRef[];
  cloud: Cloud;
  bySource: Map<string, { status: string; records: number; notes: string }> | null;
  manifestGaps: ManifestGap[];
  collected: Set<string>;
  gapByName: Map<string, { detail?: string }>;
}) {
  const meta = COLLECTOR_ASPECT_GROUPS[group];
  const rows = refs.map((ref) => resolveRow(ref, cloud, bySource, manifestGaps, collected, gapByName));

  if (!meta) {
    return (
      <>
        {rows.map((row) => (
          <CollectorCard key={aspectRowKey(row.ref)} row={row} cloud={cloud} />
        ))}
      </>
    );
  }

  return (
    <div className="panel-collector-group">
      <div className="panel-collector-group-header">
        <ArtifactIcon
          cloud={cloud}
          collector={meta.iconCollector}
          size={22}
          className="panel-collector-icon"
        />
        <span className="panel-collector-name">{meta.label}</span>
      </div>
      <div className="panel-collector-group-rows">
        {rows.map((row) => (
          <div
            key={aspectRowKey(row.ref)}
            className="panel-collector-aspect-row"
            title={row.title}
            aria-label={`${meta.ariaPrefix} ${row.label}: ${row.statusLabel}`}
          >
            <span className="panel-collector-aspect-label">{row.label}</span>
            <CollectorCheckbox tint={row.tint} />
          </div>
        ))}
      </div>
    </div>
  );
}

export function PanelCollectors({ panel }: { panel: PanelId }) {
  const { caseId, summary } = useCase();
  const cloud = (summary?.cloud ?? "aws") as Cloud;
  const def = panelCollectors(cloud)[panel];
  const manifestQ = useQuery({
    queryKey: ["manifest", caseId],
    queryFn: () => api.manifest(caseId),
    staleTime: 60_000,
  });

  const collected = new Set(summary?.collection?.collected ?? []);
  const gapByName = new Map((summary?.collection?.gaps ?? []).map((g) => [g.name, g]));
  const manifest = manifestQ.data;
  const bySource = manifest ? aggregateManifestSources(manifest.sources ?? []) : null;
  const manifestGaps = manifest?.gaps ?? summary?.collection?.gaps ?? [];

  if (panel === "collection") {
    return null;
  }

  const segments = segmentCollectors(def.collectors);

  return (
    <div className="panel-collectors">
      <div className="panel-collectors-row">
        {segments.map((segment) => {
          if (segment.kind === "aspect-group") {
            return (
              <CollectorAspectGroup
                key={segment.group}
                group={segment.group}
                refs={segment.refs}
                cloud={cloud}
                bySource={bySource}
                manifestGaps={manifestGaps}
                collected={collected}
                gapByName={gapByName}
              />
            );
          }

          const row = resolveRow(
            segment.ref,
            cloud,
            bySource,
            manifestGaps,
            collected,
            gapByName,
          );
          return (
            <CollectorCard
              key={`${segment.ref.id}-${aspectRowKey(segment.ref)}`}
              row={row}
              cloud={cloud}
            />
          );
        })}
      </div>
    </div>
  );
}
