"use client";

import { MultiSelect } from "@/components/multiselect";
import {
  ALL_EDGE_REQUEST_COL_KEYS,
  EDGE_REQUEST_COLS,
  EDGE_SOURCE_LABEL,
  type EdgeRequestColKey,
} from "@/lib/edge-request-columns";
import type { Facets } from "@/lib/types";
import { Columns3, Filter, Search } from "lucide-react";
import { useEffect, useState } from "react";

export interface EdgeRequestFilters {
  q?: string;
  methods?: string[];
  sources?: string[];
  resources?: string[];
  statuses?: string[];
}

const EDGE_SOURCE_OPTIONS = ["elb_alb", "cloudfront"] as const;

export function EdgeRequestToolbar({
  facets,
  filters,
  visibleColumns,
  onChange,
  onColumnsChange,
  onReset,
}: {
  facets?: Facets;
  filters: EdgeRequestFilters;
  visibleColumns: EdgeRequestColKey[];
  onChange: (next: Partial<EdgeRequestFilters>) => void;
  onColumnsChange: (cols: EdgeRequestColKey[]) => void;
  onReset: () => void;
}) {
  const [search, setSearch] = useState(filters.q ?? "");

  useEffect(() => setSearch(filters.q ?? ""), [filters.q]);

  const methodOptions = (facets?.event_action ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const sourceOptions = EDGE_SOURCE_OPTIONS.map((value) => ({
    value,
    label: EDGE_SOURCE_LABEL[value] ?? value,
    count: facets?.ventra_source?.find((f) => f.value === value)?.count ?? 0,
  }));

  const resourceOptions = (facets?.resource_id ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const statusOptions = (facets?.http_status ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const columnOptions = EDGE_REQUEST_COLS.map((c) => ({
    value: c.key,
    label: c.label,
  }));

  const toggleColumn = (key: EdgeRequestColKey) => {
    const col = EDGE_REQUEST_COLS.find((c) => c.key === key);
    if (col?.locked) return;

    const cur = visibleColumns;
    const next = cur.includes(key) ? cur.filter((x) => x !== key) : [...cur, key];
    const ordered = ALL_EDGE_REQUEST_COL_KEYS.filter((k) => next.includes(k));
    if (ordered.length === 0) return;
    onColumnsChange(ordered);
  };

  return (
    <div className="ct-filter-bar">
      <div className="ct-filter-controls">
        <div className="ct-search-wrap">
          <Search className="ct-search-icon" aria-hidden />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onChange({ q: search || undefined });
            }}
            placeholder="Search requests…"
            className="ct-input ct-input-full ct-input-search"
          />
        </div>

        <MultiSelect
          label="Method"
          icon={Filter}
          options={methodOptions}
          selected={filters.methods ?? []}
          onToggle={(v) => {
            const cur = filters.methods ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ methods: next.length ? next : undefined });
          }}
          onClear={() => onChange({ methods: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Source"
          icon={Filter}
          options={sourceOptions}
          selected={filters.sources ?? []}
          onToggle={(v) => {
            const cur = filters.sources ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ sources: next.length ? next : undefined });
          }}
          onClear={() => onChange({ sources: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Resource"
          icon={Filter}
          options={resourceOptions}
          selected={filters.resources ?? []}
          onToggle={(v) => {
            const cur = filters.resources ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ resources: next.length ? next : undefined });
          }}
          onClear={() => onChange({ resources: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Status"
          icon={Filter}
          options={statusOptions}
          selected={filters.statuses ?? []}
          onToggle={(v) => {
            const cur = filters.statuses ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ statuses: next.length ? next : undefined });
          }}
          onClear={() => onChange({ statuses: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Columns"
          icon={Columns3}
          options={columnOptions}
          selected={visibleColumns}
          lockedValues={EDGE_REQUEST_COLS.filter((c) => c.locked).map((c) => c.key)}
          onToggle={(v) => toggleColumn(v as EdgeRequestColKey)}
          onClear={() => onColumnsChange(["timestamp"])}
          searchable={false}
          variant="cloudtrail"
        />

        <button type="button" onClick={onReset} className="ct-btn ct-btn-reset">
          Reset
        </button>
      </div>
    </div>
  );
}
