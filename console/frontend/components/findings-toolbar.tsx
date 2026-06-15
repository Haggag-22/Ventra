"use client";

import { MultiSelect } from "@/components/multiselect";
import { FINDING_CLASS_OPTIONS } from "@/lib/finding-class";
import { ventraSourceLabel } from "@/lib/finding-origin";
import {
  ALL_FINDING_COL_KEYS,
  FINDING_COLS,
  type FindingColKey,
} from "@/lib/findings-columns";
import { fmtNum } from "@/lib/format";
import { SEVERITY_META, SEVERITY_ORDER } from "@/lib/severity";
import type { Facets } from "@/lib/types";
import { Columns3, Filter } from "lucide-react";

export interface FindingsFilters {
  severity?: string[];
  source?: string[];
  findingClass?: string[];
}

export function FindingsToolbar({
  facets,
  filters,
  total,
  visibleColumns = ALL_FINDING_COL_KEYS,
  onChange,
  onColumnsChange,
  onReset,
}: {
  facets?: Facets;
  filters: FindingsFilters;
  total: number;
  matched?: number;
  visibleColumns?: FindingColKey[];
  onChange: (next: Partial<FindingsFilters>) => void;
  onColumnsChange?: (cols: FindingColKey[]) => void;
  onReset: () => void;
}) {
  const severityOptions = SEVERITY_ORDER.map((s) => ({
    value: s,
    label: SEVERITY_META[s].label,
    count: facets?.event_severity.find((f) => f.value === s)?.count,
  }));

  const sourceOptions = (facets?.ventra_source ?? []).map((f) => ({
    value: f.value,
    label: ventraSourceLabel(f.value),
    count: f.count,
  }));

  const classOptions = FINDING_CLASS_OPTIONS.map((value) => ({
    value,
    count: facets?.finding_class?.find((f) => f.value === value)?.count ?? 0,
  })).filter((o) => o.count > 0);

  const columnOptions = FINDING_COLS.map((c) => ({ value: c.key, label: c.label }));

  const toggleColumn = (key: FindingColKey) => {
    if (!onColumnsChange) return;
    const col = FINDING_COLS.find((c) => c.key === key);
    if (col?.locked) return;
    const next = visibleColumns.includes(key)
      ? visibleColumns.filter((x) => x !== key)
      : [...visibleColumns, key];
    const ordered = ALL_FINDING_COL_KEYS.filter((k) => next.includes(k));
    if (ordered.length === 0) return;
    onColumnsChange(ordered);
  };

  return (
    <div className="ct-filter-bar">
      <div className="ct-filter-stats">
        <span className="ct-status-badge">
          <span className="ct-status-dot bg-ok-green" />
          Total: {fmtNum(total)}
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

        <MultiSelect
          label="Class"
          icon={Filter}
          options={classOptions}
          selected={filters.findingClass ?? []}
          onToggle={(v) => {
            const cur = filters.findingClass ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ findingClass: next.length ? next : undefined });
          }}
          onClear={() => onChange({ findingClass: undefined })}
          variant="cloudtrail"
        />

        {onColumnsChange && (
          <MultiSelect
            label="Columns"
            icon={Columns3}
            options={columnOptions}
            selected={visibleColumns}
            lockedValues={FINDING_COLS.filter((c) => c.locked).map((c) => c.key)}
            onToggle={(v) => toggleColumn(v as FindingColKey)}
            onClear={() => onColumnsChange?.(["timestamp"])}
            searchable={false}
            variant="cloudtrail"
          />
        )}

        <button type="button" onClick={onReset} className="ct-btn ct-btn-reset">
          Reset
        </button>
      </div>
    </div>
  );
}
