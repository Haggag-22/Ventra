"use client";

import type { Facets } from "@/lib/types";
import { SEVERITY_META, SEVERITY_ORDER } from "@/lib/severity";
import { cn } from "@/lib/utils";
import { fmtNum } from "@/lib/format";
import { X } from "lucide-react";
import { useFilters } from "@/lib/useFilters";

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-border px-3 py-3">
      <div className="mb-2 text-2xs font-medium uppercase tracking-wide text-fg-subtle">{title}</div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function Row({
  active,
  onClick,
  label,
  count,
  swatch,
}: {
  active: boolean;
  onClick: () => void;
  label: React.ReactNode;
  count?: number;
  swatch?: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-xs transition-colors",
        active ? "bg-accent/12 text-fg" : "text-fg-subtle hover:bg-surface-2 hover:text-fg",
      )}
    >
      <span
        className={cn(
          "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded border",
          active ? "border-accent bg-accent" : "border-border",
        )}
      >
        {active && <span className="h-1.5 w-1.5 rounded-sm bg-accent-fg" />}
      </span>
      {swatch}
      <span className="flex-1 truncate">{label}</span>
      {count !== undefined && <span className="mono text-2xs text-fg-subtle">{fmtNum(count)}</span>}
    </button>
  );
}

export function FilterRail({ facets }: { facets?: Facets }) {
  const { params, toggleArray, setParam, clearAll, activeCount } = useFilters();
  const selectedSources = (params.source as string[]) ?? [];
  const selectedSev = (params.severity as string[]) ?? [];
  const selectedCat = (params.category as string[]) ?? [];

  return (
    <div className="flex h-full w-[230px] shrink-0 flex-col border-r border-border bg-surface">
      <div className="flex items-center justify-between px-3 py-2.5 border-b border-border">
        <span className="text-xs font-semibold text-fg">Filters</span>
        {activeCount > 0 && (
          <button
            onClick={clearAll}
            className="flex items-center gap-1 text-2xs text-fg-subtle hover:text-fg"
          >
            <X className="h-3 w-3" /> Clear ({activeCount})
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Active pivots surfaced explicitly so the analyst knows what's scoping the view. */}
        {(params.related_ip || params.related_user || params.related_resource) && (
          <Group title="Pivoted on">
            {params.related_ip && (
              <ActivePivot label={`IP ${params.related_ip}`} onClear={() => setParam("related_ip")} />
            )}
            {params.related_user && (
              <ActivePivot
                label={`User ${params.related_user}`}
                onClear={() => setParam("related_user")}
              />
            )}
            {params.related_resource && (
              <ActivePivot
                label={`Resource ${params.related_resource}`}
                onClear={() => setParam("related_resource")}
              />
            )}
          </Group>
        )}

        <Group title="Severity">
          {SEVERITY_ORDER.map((s) => {
            const meta = SEVERITY_META[s];
            const count = facets?.event_severity.find((f) => f.value === s)?.count;
            return (
              <Row
                key={s}
                active={selectedSev.includes(s)}
                onClick={() => toggleArray("severity", s)}
                label={meta.label}
                count={count}
                swatch={<span className={cn("h-2 w-2 rounded-full", meta.dot)} />}
              />
            );
          })}
        </Group>

        <Group title="Source">
          {(facets?.harbor_source ?? []).map((f) => (
            <Row
              key={f.value}
              active={selectedSources.includes(f.value)}
              onClick={() => toggleArray("source", f.value)}
              label={f.value}
              count={f.count}
            />
          ))}
        </Group>

        <Group title="Category">
          {["authentication", "iam", "network", "data", "configuration", "threat", "session"].map(
            (c) => (
              <Row
                key={c}
                active={selectedCat.includes(c)}
                onClick={() => toggleArray("category", c)}
                label={c}
              />
            ),
          )}
        </Group>

        <Group title="Outcome">
          {["success", "failure"].map((o) => (
            <Row
              key={o}
              active={params.outcome === o}
              onClick={() => setParam("outcome", params.outcome === o ? undefined : o)}
              label={o === "failure" ? "Denied / failed" : "Success"}
            />
          ))}
        </Group>

        {facets?.user_name && facets.user_name.length > 0 && (
          <Group title="Top principals">
            {facets.user_name.slice(0, 8).map((f) => (
              <Row
                key={f.value}
                active={params.related_user === f.value}
                onClick={() =>
                  setParam("related_user", params.related_user === f.value ? undefined : f.value)
                }
                label={f.value}
                count={f.count}
              />
            ))}
          </Group>
        )}
      </div>
    </div>
  );
}

function ActivePivot({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <div className="flex items-center justify-between rounded-md bg-accent/12 px-2 py-1">
      <span className="mono truncate text-2xs text-accent">{label}</span>
      <button onClick={onClear} className="text-accent/70 hover:text-accent">
        <X className="h-3 w-3" />
      </button>
    </div>
  );
}
