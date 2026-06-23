"use client";

import { MultiSelect, SelectDropdown } from "@/components/multiselect";
import {
  ALL_K8S_AUDIT_COL_KEYS,
  K8S_AUDIT_COLS,
  type K8sAuditColKey,
} from "@/lib/kubernetes-audit-columns";
import type { Facets } from "@/lib/types";
import { Columns3, Filter, Search } from "lucide-react";
import { useEffect, useState } from "react";

const ORDER_OPTIONS = [
  { value: "desc", label: "Descending" },
  { value: "asc", label: "Ascending" },
];

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"] as const;
const OUTCOME_OPTIONS = ["success", "failure", "unknown"] as const;

export interface K8sAuditFilters {
  q?: string;
  actions?: string[];
  severities?: string[];
  outcomes?: string[];
  regions?: string[];
  users?: string[];
  order?: string;
  user?: string;
  ip?: string;
}

export function KubernetesAuditToolbar({
  facets,
  filters,
  visibleColumns,
  onChange,
  onColumnsChange,
  onApply,
  onReset,
}: {
  facets?: Facets;
  filters: K8sAuditFilters;
  visibleColumns: K8sAuditColKey[];
  onChange: (next: Partial<K8sAuditFilters>) => void;
  onColumnsChange: (cols: K8sAuditColKey[]) => void;
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
  const regionOptions = (facets?.cloud_region ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));
  const principalOptions = (facets?.user_name ?? []).map((f) => ({
    value: f.value,
    count: f.count,
  }));
  const severityOptions = SEVERITY_OPTIONS.map((value) => ({
    value,
    count: facets?.event_severity?.find((f) => f.value === value)?.count ?? 0,
  }));
  const outcomeOptions = OUTCOME_OPTIONS.map((value) => ({
    value,
    count: facets?.event_outcome?.find((f) => f.value === value)?.count ?? 0,
  }));

  const columnOptions = K8S_AUDIT_COLS.map((c) => ({
    value: c.key,
    label: c.label,
  }));

  const toggleColumn = (key: K8sAuditColKey) => {
    const col = K8S_AUDIT_COLS.find((c) => c.key === key);
    if (col?.locked) return;

    const cur = visibleColumns;
    const next = cur.includes(key) ? cur.filter((x) => x !== key) : [...cur, key];
    const ordered = ALL_K8S_AUDIT_COL_KEYS.filter((k) => next.includes(k));
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
            placeholder="Search audit events…"
            className="ct-input ct-input-full ct-input-search"
          />
        </div>

        <MultiSelect
          label="Actions"
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
          label="Severity"
          icon={Filter}
          options={severityOptions}
          selected={filters.severities ?? []}
          onToggle={(v) => {
            const cur = filters.severities ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ severities: next.length ? next : undefined });
          }}
          onClear={() => onChange({ severities: undefined })}
          variant="cloudtrail"
        />

        <MultiSelect
          label="Outcome"
          icon={Filter}
          options={outcomeOptions}
          selected={filters.outcomes ?? []}
          onToggle={(v) => {
            const cur = filters.outcomes ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ outcomes: next.length ? next : undefined });
          }}
          onClear={() => onChange({ outcomes: undefined })}
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

        <MultiSelect
          label="Users"
          icon={Filter}
          options={principalOptions}
          selected={filters.users ?? []}
          onToggle={(v) => {
            const cur = filters.users ?? [];
            const next = cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v];
            onChange({ users: next.length ? next : undefined });
          }}
          onClear={() => onChange({ users: undefined })}
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
          lockedValues={K8S_AUDIT_COLS.filter((c) => c.locked).map((c) => c.key)}
          onToggle={(v) => toggleColumn(v as K8sAuditColKey)}
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
          placeholder="User / service account"
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
