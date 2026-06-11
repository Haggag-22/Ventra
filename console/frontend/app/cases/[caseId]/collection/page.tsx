"use client";

import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Card, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { CATALOG, CLOUD_IMPLEMENTED, type Cloud } from "@/lib/catalog";
import {
  aggregateManifestSources,
  catalogItems,
  profileCollectorIds,
  resolveCollectorCoverage,
  unmappedGaps,
  type CoverageState,
} from "@/lib/collection-coverage";
import { fmtNum } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckSquare,
  ListChecks,
  MinusSquare,
  Square,
  XSquare,
} from "lucide-react";

const STATE_META: Record<
  CoverageState,
  { label: string; icon: typeof Square; tone: string; collected: boolean }
> = {
  collected: { label: "Collected", icon: CheckSquare, tone: "text-ok-green", collected: true },
  partial: { label: "Partial", icon: AlertTriangle, tone: "text-warn-amber", collected: true },
  empty: { label: "No records", icon: MinusSquare, tone: "text-warn-amber", collected: false },
  not_enabled: { label: "Not available", icon: Square, tone: "text-warn-amber", collected: false },
  denied: { label: "Access denied", icon: XSquare, tone: "text-bad-red", collected: false },
  not_run: { label: "Not run", icon: Square, tone: "text-fg-subtle", collected: false },
  not_in_profile: { label: "Not in profile", icon: Square, tone: "text-fg-subtle", collected: false },
};

export default function CollectionPage() {
  const { caseId } = useCase();
  const manifestQ = useQuery({ queryKey: ["manifest", caseId], queryFn: () => api.manifest(caseId) });
  const summaryQ = useQuery({ queryKey: ["summary", caseId], queryFn: () => api.summary(caseId) });

  if (manifestQ.isLoading || summaryQ.isLoading || !manifestQ.data || !summaryQ.data)
    return <LoadingPanel label="Loading collection status…" />;

  const manifest = manifestQ.data;
  const cloud = (manifest.cloud ?? "aws") as Cloud;
  const groups = CATALOG[cloud] ?? [];
  const profileName = manifest.profile?.name ?? summaryQ.data.profile?.name ?? "baseline";
  const profileIds = new Set(profileCollectorIds(profileName));
  const bySource = aggregateManifestSources(manifest.sources ?? []);
  const gaps: { name: string; reason: string; detail: string }[] = manifest.gaps ?? [];
  const catalogIds = new Set(catalogItems(cloud).map((i) => i.id));

  const resolve = (id: string) =>
    resolveCollectorCoverage(id, bySource, gaps, profileIds.has(id));

  const allItems = groups.flatMap((g) => g.items);
  const resolved = allItems.map((it) => ({ it, r: resolve(it.id) }));

  const profileItems = resolved.filter((x) => x.r.inProfile);
  const profileCollected = profileItems.filter(
    (x) => x.r.state === "collected" || x.r.state === "partial",
  ).length;
  const profileTotal = profileItems.length;

  const implementedCollected = resolved.filter(
    (x) => x.r.state === "collected" || x.r.state === "partial",
  ).length;

  const extraGaps = unmappedGaps(gaps, catalogIds);
  const profilePct = Math.round((profileCollected / Math.max(profileTotal, 1)) * 100);

  return (
    <>
      <PanelHeader
        icon={ListChecks}
        title="Collection Coverage"
        panel="collection"
        actions={
          <span className="text-xs text-fg-subtle">
            <span className="font-medium text-fg">{profileName}</span>
            <span className="mx-1.5 text-border">·</span>
            <span className="text-ok-green font-medium">{profileCollected}</span> / {profileTotal}{" "}
            in profile
          </span>
        }
      />
      <PanelBody className="space-y-5">
        {!CLOUD_IMPLEMENTED[cloud] && (
          <div className="rounded-lg border border-warn-amber/30 bg-warn-amber/10 px-4 py-3 text-xs text-warn-amber">
            {cloud.toUpperCase()} collectors are scaffolded but not yet implemented — these
            artifacts are shown as planned coverage.
          </div>
        )}

        <Card className="p-4">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-fg-subtle">
            <span className="stat-label">Profile coverage ({profileName})</span>
            <span className="mono">{profilePct}%</span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2">
            <div
              className="h-full rounded-full bg-ok-green"
              style={{ width: `${profilePct}%` }}
            />
          </div>
          <div className="mt-2 text-2xs text-fg-subtle">
            {implementedCollected} of {allItems.length} implemented {cloud.toUpperCase()} collectors
            have data in this case.
          </div>
          <div className="mt-3 flex flex-wrap gap-3 text-2xs text-fg-subtle">
            <Legend icon={CheckSquare} tone="text-ok-green" label="Collected" />
            <Legend icon={AlertTriangle} tone="text-warn-amber" label="Partial" />
            <Legend icon={MinusSquare} tone="text-warn-amber" label="No records" />
            <Legend icon={Square} tone="text-warn-amber" label="Not available" />
            <Legend icon={XSquare} tone="text-bad-red" label="Access denied" />
            <Legend icon={Square} tone="text-fg-subtle" label="Not in profile" />
          </div>
        </Card>

        {groups.map((group) => (
          <Card key={group.category} className="overflow-hidden">
            <div className="border-b border-border px-4 py-2.5 text-sm font-semibold">
              {group.category}
            </div>
            <div className="divide-y divide-border">
              {group.items.map((item) => {
                const r = resolve(item.id);
                const meta = STATE_META[r.state];
                const Icon = meta.icon;
                return (
                  <div key={item.id} className="flex items-start gap-3 px-4 py-3">
                    <Icon className={cn("mt-0.5 h-5 w-5 shrink-0", meta.tone)} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-fg">{item.label}</span>
                        <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-2xs uppercase tracking-wide text-fg-subtle">
                          Tier {item.tier}
                        </span>
                        {r.inProfile && (
                          <span className="rounded border border-accent/25 bg-accent/10 px-1.5 py-0.5 text-2xs text-accent">
                            In profile
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 text-xs text-fg-subtle">{item.description}</div>
                      {r.detail && r.state !== "collected" && (
                        <div className="mt-1 text-2xs text-fg-subtle/80 italic">{r.detail}</div>
                      )}
                      {r.gaps.length > 0 && r.state === "partial" && (
                        <ul className="mt-1.5 space-y-0.5 text-2xs text-warn-amber/90">
                          {r.gaps.map((g) => (
                            <li key={g.name}>
                              <span className="mono">{g.name}</span>: {g.detail}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                    <div className="shrink-0 text-right">
                      <div className={cn("text-xs font-medium", meta.tone)}>{meta.label}</div>
                      {(r.state === "collected" || r.state === "partial") && r.records > 0 && (
                        <div className="mono text-2xs text-fg-subtle">
                          {fmtNum(r.records)} records
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        ))}

        {extraGaps.length > 0 && (
          <Card className="overflow-hidden">
            <div className="border-b border-border px-4 py-2.5 text-sm font-semibold">
              Additional notes
            </div>
            <div className="divide-y divide-border">
              {extraGaps.map((g, i) => (
                <div key={i} className="flex items-start gap-3 px-4 py-2.5">
                  <Square className="mt-0.5 h-4 w-4 shrink-0 text-warn-amber" />
                  <div className="min-w-0 flex-1">
                    <span className="mono text-xs text-fg">{g.name}</span>
                    <span className="ml-2 text-2xs text-fg-subtle">{g.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </PanelBody>
    </>
  );
}

function Legend({ icon: Icon, tone, label }: { icon: typeof Square; tone: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <Icon className={cn("h-3.5 w-3.5", tone)} />
      {label}
    </span>
  );
}
