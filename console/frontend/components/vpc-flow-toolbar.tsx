"use client";

import { MultiSelect, SelectDropdown } from "@/components/multiselect";
import {
  ALL_VPC_FLOW_COL_KEYS,
  VPC_FLOW_COLS,
  type VpcFlowColKey,
} from "@/lib/vpc-flow-columns";
import type { Facets } from "@/lib/types";
import { Columns3, Filter, Search } from "lucide-react";
import { useEffect, useState } from "react";

const ORDER_OPTIONS = [
  { value: "desc", label: "Descending" },
  { value: "asc", label: "Ascending" },
];

export interface VpcFlowFilters {
  q?: string;
  actions?: string[];
  outcomes?: string[];
  regions?: string[];
  sourceIps?: string[];
  destIps?: string[];
  destPorts?: string[];
  order?: string;
}

export function VpcFlowToolbar({
  facets,
  filters,
  visibleColumns,
  onChange,
  onColumnsChange,
  onReset,
}: {
  facets?: Facets;
  filters: VpcFlowFilters;
  visibleColumns: VpcFlowColKey[];
  onChange: (next: Partial<VpcFlowFilters>) => void;
  onColumnsChange: (cols: VpcFlowColKey[]) => void;
  onReset: () => void;
}) {
  const [search, setSearch] = useState(filters.q ?? "");

  useEffect(() => setSearch(filters.q ?? ""), [filters.q]);

  const actionOptions = (facets?.event_action ?? []).map((f) => ({
    value: f.value,
    label: f.value.toUpperCase(),
    count: f.count,
  }));

  const outcomeOptions = (facets?.event_outcome ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const regionOptions = (facets?.cloud_region ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const sourceIpOptions = (facets?.source_ip ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const destIpOptions = (facets?.dest_ip ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const destPortOptions = (facets?.dest_port ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const columnOptions = VPC_FLOW_COLS.map((c) => ({
    value: c.key,
    label: c.label,
  }));

  const toggleColumn = (key: VpcFlowColKey) => {
    const col = VPC_FLOW_COLS.find((c) => c.key === key);
    if (col?.locked) return;

    const cur = visibleColumns;
    const next = cur.includes(key) ? cur.filter((x) => x !== key) : [...cur, key];
    const ordered = ALL_VPC_FLOW_COL_KEYS.filter((k) => next.includes(k));
    if (ordered.length === 0) return;
    onColumnsChange(ordered);
  };

  const toggleList = (
    key: keyof Pick<VpcFlowFilters, "actions" | "outcomes" | "regions" | "sourceIps" | "destIps" | "destPorts">,
    value: string,
  ) => {
    const cur = filters[key] ?? [];
    const next = cur.includes(value) ? cur.filter((x) => x !== value) : [...cur, value];
    onChange({ [key]: next.length ? next : undefined });
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
            placeholder="Search flows…"
            className="ct-input ct-input-full ct-input-search"
          />
        </div>

        <MultiSelect
          label="Action"
          icon={Filter}
          options={actionOptions}
          selected={filters.actions ?? []}
          onToggle={(v) => toggleList("actions", v)}
          onClear={() => onChange({ actions: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Outcome"
          icon={Filter}
          options={outcomeOptions}
          selected={filters.outcomes ?? []}
          onToggle={(v) => toggleList("outcomes", v)}
          onClear={() => onChange({ outcomes: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Region"
          icon={Filter}
          options={regionOptions}
          selected={filters.regions ?? []}
          onToggle={(v) => toggleList("regions", v)}
          onClear={() => onChange({ regions: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Source IP"
          icon={Filter}
          options={sourceIpOptions}
          selected={filters.sourceIps ?? []}
          onToggle={(v) => toggleList("sourceIps", v)}
          onClear={() => onChange({ sourceIps: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Dest IP"
          icon={Filter}
          options={destIpOptions}
          selected={filters.destIps ?? []}
          onToggle={(v) => toggleList("destIps", v)}
          onClear={() => onChange({ destIps: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Dest port"
          icon={Filter}
          options={destPortOptions}
          selected={filters.destPorts ?? []}
          onToggle={(v) => toggleList("destPorts", v)}
          onClear={() => onChange({ destPorts: undefined })}
          variant="cloudtrail"
        />

        <select
          className="ct-select"
          value="time"
          disabled
          title="Sort by"
          aria-label="Sort by"
        >
          <option value="time">Time</option>
        </select>

        <SelectDropdown
          value={filters.order ?? "desc"}
          options={ORDER_OPTIONS}
          onChange={(v) => onChange({ order: v })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Columns"
          icon={Columns3}
          options={columnOptions}
          selected={visibleColumns}
          lockedValues={VPC_FLOW_COLS.filter((c) => c.locked).map((c) => c.key)}
          onToggle={(v) => toggleColumn(v as VpcFlowColKey)}
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
