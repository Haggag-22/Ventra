"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Badge, Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import type { Connection } from "@/lib/api";
import type { CasePlatform } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { ChevronDown, Cloud, Pencil, Plus, Search, Trash2, Zap } from "lucide-react";
import { useMemo, useRef, useState, type ReactNode } from "react";
import {
  formatAddedDate,
  providerConnectionStatus,
  providerDisplayName,
  providerScopeSubtitle,
  shortPlatformLabel,
  type ProviderConnectionStatus,
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

/** Locale-friendly date+time for last tested (matches ADDED date style, with time). */
function lastTestedLabel(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

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

const STATUS_BADGE: Record<
  ProviderConnectionStatus,
  { label: string; className: string; dotClassName: string }
> = {
  connected: {
    label: "Connected",
    className: "border-ok-green/40 bg-ok-green/10 text-ok-green",
    dotClassName: "bg-ok-green",
  },
  failed: {
    label: "Failed",
    className: "border-bad-red/40 bg-bad-red/10 text-bad-red",
    dotClassName: "bg-bad-red",
  },
  untested: {
    label: "Untested",
    className: "border-warn-amber/40 bg-warn-amber/10 text-warn-amber",
    dotClassName: "bg-warn-amber",
  },
};

function StatusBadge({ status }: { status: ProviderConnectionStatus }) {
  const cfg = STATUS_BADGE[status];
  return (
    <Badge className={cn("table-badge no-underline shrink-0 gap-1.5", cfg.className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dotClassName)} />
      {cfg.label}
    </Badge>
  );
}

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
      <button
        type="button"
        onClick={onEdit}
        className={btnClass}
        aria-label="Edit connection"
        title="Edit"
      >
        <Pencil className="h-3.5 w-3.5" />
      </button>
      <button
        type="button"
        onClick={onDelete}
        className={cn(btnClass, "hover:border-bad-red/40 hover:bg-bad-red/10 hover:text-bad-red")}
        aria-label="Delete connection"
        title="Delete"
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
    if (status !== "all" && providerConnectionStatus(conn) !== status) return false;
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
  const tableRef = useRef<HTMLDivElement>(null);
  const [filters, setFilters] = useState<ProviderFilters>({
    platform: "all",
    status: "all",
    search: "",
  });

  const filtered = useMemo(() => filterConnections(connections, filters), [connections, filters]);
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
        tableRef,
      );
      return () => mm.revert();
    },
    { scope: tableRef, dependencies: [filterKey, filtered.length], revertOnUpdate: true },
  );

  if (loading) {
    return <LoadingPanel label="Loading connections…" />;
  }

  if (connections.length === 0) {
    return (
      <Card>
        <EmptyState
          icon={Cloud}
          title="No connections yet"
          description="Connect a cloud provider to run collections from the Ventra server using named credentials on the host."
          action={
            <Button variant="primary" icon={Plus} onClick={onAdd}>
              Add connection
            </Button>
          }
        />
      </Card>
    );
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
          <option value="kubernetes">Kubernetes</option>
        </FilterSelect>
        <FilterSelect
          label="Filter by status"
          value={filters.status}
          onChange={(status) => setFilters((f) => ({ ...f, status }))}
        >
          <option value="all">All status</option>
          <option value="connected">Connected</option>
          <option value="untested">Untested</option>
          <option value="failed">Failed</option>
        </FilterSelect>

        <div className="relative ml-auto w-52 shrink-0">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
          <input
            type="search"
            value={filters.search}
            onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
            placeholder="Search connections…"
            className={cn(
              "h-9 w-full rounded-full border border-border bg-surface pl-9 pr-3 text-sm text-fg",
              "placeholder:text-fg-faint focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/40",
            )}
          />
        </div>
      </div>

      <div className="flex items-center justify-between px-1">
        <span className="text-xs text-fg-faint">
          {filtered.length} of {connections.length} connection{connections.length === 1 ? "" : "s"}
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-surface-2/30 px-6 py-12 text-center text-sm text-fg-subtle">
          No connections match your filters.
        </div>
      ) : (
        <div ref={tableRef}>
          <Card className="glass-card-glow overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="table-head-row">
                    <th className="table-header-cell">Name</th>
                    <th className="table-header-cell-center">Platform</th>
                    <th className="table-header-cell-center">Status</th>
                    <th className="table-header-cell">Last tested</th>
                    <th className="table-header-cell">Added</th>
                    <th className="table-header-cell-center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((conn) => {
                    const status = providerConnectionStatus(conn);
                    const scope = providerScopeSubtitle(conn);
                    const displayName = providerDisplayName(conn);
                    const altName =
                      conn.alias?.trim() &&
                      conn.name.trim() &&
                      conn.name.trim() !== conn.alias.trim()
                        ? conn.name.trim()
                        : null;
                    const subtitle = [altName, scope].filter(Boolean).join(" · ");

                    return (
                      <tr
                        key={conn.id}
                        className="provider-row border-b border-border/60 last:border-0 transition-colors hover:bg-surface-2/30"
                      >
                        <td className="table-cell font-medium">
                          <div className="min-w-0">
                            <p className="truncate text-sm font-medium text-fg">{displayName}</p>
                            {subtitle && (
                              <p className="truncate text-xs font-normal text-fg-subtle">{subtitle}</p>
                            )}
                          </div>
                        </td>
                        <td className="table-cell-center">
                          <span
                            className="inline-flex justify-center"
                            title={shortPlatformLabel(conn.platform)}
                          >
                            <CloudProviderIcon cloud={conn.platform as CasePlatform} />
                          </span>
                        </td>
                        <td className="table-cell-center">
                          <StatusBadge status={status} />
                        </td>
                        <td className="table-cell-muted mono whitespace-nowrap">
                          {lastTestedLabel(conn.last_tested_at)}
                        </td>
                        <td className="table-cell-muted mono whitespace-nowrap">
                          {formatAddedDate(conn.created_at)}
                        </td>
                        <td className="table-cell-center">
                          <RowActions
                            testing={testingId === conn.id}
                            onEdit={() => onEdit(conn)}
                            onTest={() => onTest(conn.id)}
                            onDelete={() => onDelete(conn)}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
