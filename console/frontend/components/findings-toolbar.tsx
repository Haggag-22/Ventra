"use client";

import { MultiSelect } from "@/components/multiselect";
import { harborSourceLabel } from "@/lib/finding-origin";
import { fmtNum } from "@/lib/format";
import { SEVERITY_META, SEVERITY_ORDER } from "@/lib/severity";
import type { Facets } from "@/lib/types";
import { Filter } from "lucide-react";

export interface FindingsFilters {
  severity?: string[];
  source?: string[];
}

export function FindingsToolbar({
  facets,
  filters,
  total,
  matched,
  onChange,
  onReset,
}: {
  facets?: Facets;
  filters: FindingsFilters;
  total: number;
  matched: number;
  onChange: (next: Partial<FindingsFilters>) => void;
  onReset: () => void;
}) {
  const severityOptions = SEVERITY_ORDER.map((s) => ({
    value: s,
    label: SEVERITY_META[s].label,
    count: facets?.event_severity.find((f) => f.value === s)?.count,
  }));

  const sourceOptions = (facets?.harbor_source ?? []).map((f) => ({
    value: f.value,
    label: harborSourceLabel(f.value),
    count: f.count,
  }));

  return (
    <div className="ct-filter-bar">
      <div className="ct-filter-stats">
        <span className="ct-status-badge">
          <span className="ct-status-dot bg-ok-green" />
          Total: {fmtNum(total)}
        </span>
        <span className="ct-status-badge">
          <span className="ct-status-dot bg-accent" />
          Matched: {fmtNum(matched)}
        </span>
      </div>

      <div className="ct-filter-controls">
        <MultiSelect
          label="Severity"
          icon={Filter}
          options={severityOptions}
          selected={filters.severity ?? []}
          onToggle={(v) => {
            const cur = filters.severity ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ severity: next.length ? next : undefined });
          }}
          onClear={() => onChange({ severity: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Source"
          icon={Filter}
          options={sourceOptions}
          selected={filters.source ?? []}
          onToggle={(v) => {
            const cur = filters.source ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ source: next.length ? next : undefined });
          }}
          onClear={() => onChange({ source: undefined })}
          variant="cloudtrail"
        />

        <button type="button" onClick={onReset} className="ct-btn ct-btn-reset">
          Reset
        </button>
      </div>
    </div>
  );
}
