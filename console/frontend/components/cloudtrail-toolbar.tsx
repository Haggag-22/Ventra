"use client";

import { MultiSelect, SelectDropdown } from "@/components/multiselect";
import {
  ALL_CLOUDTRAIL_COL_KEYS,
  CLOUDTRAIL_COLS,
  type CloudTrailColKey,
} from "@/lib/cloudtrail-columns";
import { fmtNum } from "@/lib/format";
import type { Facets } from "@/lib/types";
import { Columns3, Filter, Search } from "lucide-react";
import { useEffect, useState } from "react";

const ORDER_OPTIONS = [
  { value: "desc", label: "Descending" },
  { value: "asc", label: "Ascending" },
];

export interface CloudTrailFilters {
  q?: string;
  actions?: string[];
  services?: string[];
  regions?: string[];
  order?: string;
  user?: string;
  ip?: string;
}

export function CloudTrailToolbar({
  facets,
  filters,
  total,
  matched,
  visibleColumns,
  onChange,
  onColumnsChange,
  onApply,
  onReset,
}: {
  facets?: Facets;
  filters: CloudTrailFilters;
  total: number;
  matched: number;
  visibleColumns: CloudTrailColKey[];
  onChange: (next: Partial<CloudTrailFilters>) => void;
  onColumnsChange: (cols: CloudTrailColKey[]) => void;
  onApply: () => void;
  onReset: () => void;
}) {
  const [search, setSearch] = useState(filters.q ?? "");
  const [user, setUser] = useState(filters.user ?? "");
  const [ip, setIp] = useState(filters.ip ?? "");

  useEffect(() => setSearch(filters.q ?? ""), [filters.q]);
  useEffect(() => setUser(filters.user ?? ""), [filters.user]);
  useEffect(() => setIp(filters.ip ?? ""), [filters.ip]);

  const actionOptions = (facets?.event_action ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));
  const serviceOptions = (facets?.cloud_service ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));
  const regionOptions = (facets?.cloud_region ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));

  const columnOptions = CLOUDTRAIL_COLS.map((c) => ({
    value: c.key,
    label: c.label,
  }));

  const toggleColumn = (key: CloudTrailColKey) => {
    const col = CLOUDTRAIL_COLS.find((c) => c.key === key);
    if (col?.locked) return;

    const cur = visibleColumns;
    const next = cur.includes(key) ? cur.filter((x) => x !== key) : [...cur, key];
    const ordered = ALL_CLOUDTRAIL_COL_KEYS.filter((k) => next.includes(k));
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
        <span className="ct-status-badge">
          <span className="ct-status-dot bg-accent" />
          Matched: {fmtNum(matched)}
        </span>
      </div>

      <div className="ct-filter-controls">
        <div className="ct-search-wrap">
          <Search className="ct-search-icon" aria-hidden />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onChange({ q: search || undefined });
            }}
            placeholder="Search events…"
            className="ct-input ct-input-full ct-input-search"
          />
        </div>

        <MultiSelect
          label="Event Names"
          icon={Filter}
          options={actionOptions}
          selected={filters.actions ?? []}
          onToggle={(v) => {
            const cur = filters.actions ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ actions: next.length ? next : undefined });
          }}
          onClear={() => onChange({ actions: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Services"
          icon={Filter}
          options={serviceOptions}
          selected={filters.services ?? []}
          onToggle={(v) => {
            const cur = filters.services ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ services: next.length ? next : undefined });
          }}
          onClear={() => onChange({ services: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Regions"
          icon={Filter}
          options={regionOptions}
          selected={filters.regions ?? []}
          onToggle={(v) => {
            const cur = filters.regions ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ regions: next.length ? next : undefined });
          }}
          onClear={() => onChange({ regions: undefined })}
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
          lockedValues={CLOUDTRAIL_COLS.filter((c) => c.locked).map((c) => c.key)}
          onToggle={(v) => toggleColumn(v as CloudTrailColKey)}
          onClear={() => onColumnsChange(["timestamp"])}
          searchable={false}
          variant="cloudtrail"
        />

        <button type="button" onClick={onReset} className="ct-btn ct-btn-reset">
          Reset
        </button>
      </div>

      <div className="ct-filter-advanced">
        <input
          value={user}
          onChange={(e) => setUser(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onApply()}
          placeholder="User / ARN"
          className="ct-input ct-input-advanced"
        />
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onApply()}
          placeholder="Source IP"
          className="ct-input ct-input-advanced"
        />
        <button
          type="button"
          onClick={() => {
            onChange({
              user: user || undefined,
              ip: ip || undefined,
            });
            onApply();
          }}
          className="ct-btn ct-apply shrink-0"
        >
          Apply
        </button>
      </div>
    </div>
  );
}
