"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Badge, Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import type { Connection } from "@/lib/api";
import type { CasePlatform } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { ChevronDown, Cloud, Pencil, Search, Trash2, Zap } from "lucide-react";
import { useMemo, useRef, useState, type ReactNode } from "react";
import {
  formatAddedDate,
  formatProviderDate,
  isProviderConnected,
  providerDisplayName,
  providerScopeSubtitle,
  shortPlatformLabel,
} from "./types";

export type ProviderFilters = {
  platform: string;
  status: string;
  search: string;
};

type ProvidersTableProps = {
  connections: Connection[];
  loading: boolean;
  testingId: string | null;
  onAdd: () => void;
  onEdit: (conn: Connection) => void;
  onTest: (id: string) => void;
  onDelete: (conn: Connection) => void;
};

const GRID_COLS =
  "grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,0.9fr)_auto]";

function FilterSelect({
  value,
  onChange,
  label,
  children,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        className={cn(
          "h-9 appearance-none rounded-full border border-border bg-surface pl-3.5 pr-8 text-sm text-fg",
          "transition-colors hover:border-border-strong hover:bg-surface-2/60",
          "focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/40",
        )}
      >
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-faint" />
    </div>
  );
}

function StatusBadge({ connected }: { connected: boolean }) {
  return (
    <Badge
      className={cn(
        "table-badge no-underline",
        connected
          ? "border-ok-green/40 bg-ok-green/10 text-ok-green"
          : "border-border bg-surface text-fg-subtle",
      )}
    >
      {connected ? "Connected" : "Not connected"}
    </Badge>
  );
}

const CHECKBOX_CLASS = cn(
  "h-4 w-4 shrink-0 cursor-pointer appearance-none rounded",
  "border border-white/20 bg-white/5",
  "transition-colors",
  "checked:border-accent/50 checked:bg-accent/25",
  "checked:bg-[length:10px_10px] checked:bg-center checked:bg-no-repeat",
  "checked:bg-[url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' fill='none' stroke='%23a5b4fc' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M2.5 6.5 5 9l4.5-5.5'/%3E%3C/svg%3E\")]",
  "focus:outline-none focus:ring-1 focus:ring-accent/40 focus:ring-offset-0",
);

function RowActions({
  testing,
  onEdit,
  onTest,
  onDelete,
}: {
  testing: boolean;
  onEdit: () => void;
  onTest: () => void;
  onDelete: () => void;
}) {
  const btnClass =
    "inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface text-fg-subtle transition-colors hover:border-border-strong hover:bg-surface-2 hover:text-fg disabled:opacity-50";

  return (
    <div className="flex items-center justify-center gap-1.5">
      <button
        type="button"
        onClick={onTest}
        disabled={testing}
        className={btnClass}
        aria-label={testing ? "Testing connection" : "Test connection"}
        title={testing ? "Testing…" : "Test connection"}
      >
        <Zap className={cn("h-3.5 w-3.5", testing && "animate-pulse")} />
      </button>
      <button type="button" onClick={onEdit} className={btnClass} aria-label="Edit provider">
        <Pencil className="h-3.5 w-3.5" />
      </button>
      <button
        type="button"
        onClick={onDelete}
        className={cn(
          btnClass,
          "hover:border-bad-red/40 hover:bg-bad-red/10 hover:text-bad-red",
        )}
        aria-label="Delete provider"
      >
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

function filterConnections(
  rows: Connection[],
  { platform, status, search }: ProviderFilters,
): Connection[] {
  const q = search.trim().toLowerCase();
  return rows.filter((conn) => {
    if (platform !== "all" && conn.platform !== platform) return false;
    if (status === "connected" && !isProviderConnected(conn)) return false;
    if (status === "not_connected" && isProviderConnected(conn)) return false;
    if (q) {
      const haystack = [
        conn.name,
        conn.alias,
        conn.id,
        conn.platform,
        shortPlatformLabel(conn.platform),
        conn.project,
        conn.subscription,
        conn.aws_account_id,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

export function ProvidersTable({
  connections,
  loading,
  testingId,
  onAdd,
  onEdit,
  onTest,
  onDelete,
}: ProvidersTableProps) {
  const listRef = useRef<HTMLDivElement>(null);
  const [filters, setFilters] = useState<ProviderFilters>({
    platform: "all",
    status: "all",
    search: "",
  });
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const filtered = useMemo(
    () => filterConnections(connections, filters),
    [connections, filters],
  );

  const filterKey = `${filters.platform}|${filters.status}|${filters.search}`;

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(
        {
          reduceMotion: "(prefers-reduced-motion: reduce)",
          motion: "(prefers-reduced-motion: no-preference)",
        },
        (context) => {
          const reduceMotion = matchMediaReduced(context);
          gsap.from(".provider-row", {
            autoAlpha: reduceMotion ? 1 : 0,
            y: reduceMotion ? 0 : 6,
            duration: reduceMotion ? 0 : 0.22,
            stagger: reduceMotion ? 0 : 0.04,
            ease: "power2.out",
          });
        },
        listRef,
      );
      return () => mm.revert();
    },
    { scope: listRef, dependencies: [filterKey, filtered.length], revertOnUpdate: true },
  );

  const allSelected = filtered.length > 0 && filtered.every((c) => selected.has(c.id));

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((c) => c.id)));
    }
  };

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (loading) {
    return <LoadingPanel label="Loading providers…" />;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5 gap-y-2">
        <FilterSelect
          label="Filter by provider type"
          value={filters.platform}
          onChange={(platform) => setFilters((f) => ({ ...f, platform }))}
        >
          <option value="all">All providers</option>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
          <option value="gcp">GCP</option>
          <option value="m365">Microsoft 365</option>
          <option value="kubernetes">Kubernetes</option>
        </FilterSelect>
        <FilterSelect
          label="Filter by status"
          value={filters.status}
          onChange={(status) => setFilters((f) => ({ ...f, status }))}
        >
          <option value="all">All status</option>
          <option value="connected">Connected</option>
          <option value="not_connected">Not connected</option>
        </FilterSelect>
        {connections.length > 0 && (
          <span className="text-xs text-fg-faint">
            {filtered.length} of {connections.length} provider{connections.length === 1 ? "" : "s"}
          </span>
        )}
      </div>

      {connections.length === 0 ? (
        <Card>
          <EmptyState
            icon={Cloud}
            title="No providers yet"
            description="Add a cloud provider to run collections from the Ventra server using named credentials on the host."
            action={
              <Button
                variant="primary-dark"
                className="bg-accent text-accent-fg hover:bg-accent/90"
                onClick={onAdd}
              >
                Add Provider
              </Button>
            }
          />
        </Card>
      ) : (
        <Card className="glass-card-glow overflow-hidden p-5">
          <div className="mb-3 flex items-center justify-end">
            <div className="relative w-full max-w-xs">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
              <input
                type="search"
                value={filters.search}
                onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
                placeholder="Search providers…"
                className={cn(
                  "h-9 w-full rounded-lg border border-border bg-surface pl-9 pr-3 text-sm text-fg",
                  "placeholder:text-fg-faint focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/40",
                )}
              />
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-surface-2/30 px-6 py-12 text-center text-sm text-fg-subtle">
              No providers match your filters.
            </div>
          ) : (
            <>
              <div
                className={cn(
                  "mb-2 hidden gap-4 px-4 md:grid",
                  GRID_COLS,
                )}
              >
                <span className="table-header-cell flex items-center gap-3 !px-0">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    className={CHECKBOX_CLASS}
                    aria-label="Select all providers"
                  />
                  Name
                </span>
                <span className="table-header-cell-center !px-0">Provider</span>
                <span className="table-header-cell-center !px-0">Status</span>
                <span className="table-header-cell !px-0">Last tested</span>
                <span className="table-header-cell !px-0">Added</span>
                <span className="table-header-cell-center !px-0">Actions</span>
              </div>

              <div ref={listRef} className="space-y-2">
                {filtered.map((conn) => {
                  const connected = isProviderConnected(conn);
                  const scope = providerScopeSubtitle(conn);
                  const displayName = providerDisplayName(conn);
                  const showConnectionName =
                    conn.alias?.trim() && conn.name.trim() && conn.name.trim() !== conn.alias.trim();

                  return (
                    <div
                      key={conn.id}
                      className={cn(
                        "provider-row grid gap-x-4 gap-y-3 rounded-xl border border-border bg-surface-2/35 px-4 py-3 transition-colors",
                        "hover:border-border-strong hover:bg-surface-2/60",
                        GRID_COLS,
                      )}
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <input
                          type="checkbox"
                          checked={selected.has(conn.id)}
                          onChange={() => toggleOne(conn.id)}
                          className={CHECKBOX_CLASS}
                          aria-label={`Select ${displayName}`}
                        />
                        <CloudProviderIcon cloud={conn.platform as CasePlatform} />
                        <div className="min-w-0 text-left">
                          <p className="truncate text-sm font-medium text-fg">{displayName}</p>
                          {showConnectionName && (
                            <p className="truncate text-sm text-fg-subtle">{conn.name}</p>
                          )}
                          {scope && (
                            <p className="truncate text-sm text-fg-subtle">{scope}</p>
                          )}
                        </div>
                      </div>

                      <div
                        className="flex items-center justify-center"
                        title={shortPlatformLabel(conn.platform)}
                      >
                        <CloudProviderIcon cloud={conn.platform as CasePlatform} />
                      </div>

                      <div className="flex items-center justify-center">
                        <StatusBadge connected={connected} />
                      </div>

                      <div className="flex items-center text-sm font-normal text-fg-subtle">
                        {conn.last_tested_at ? formatProviderDate(conn.last_tested_at) : "Never"}
                      </div>

                      <div className="flex items-center text-sm font-normal text-fg-subtle">
                        {formatAddedDate(conn.created_at)}
                      </div>

                      <div className="flex items-center justify-center">
                        <RowActions
                          testing={testingId === conn.id}
                          onEdit={() => onEdit(conn)}
                          onTest={() => onTest(conn.id)}
                          onDelete={() => onDelete(conn)}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </Card>
      )}
    </div>
  );
}
