"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Badge, Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import type { Connection } from "@/lib/api";
import { isPlatformVisibleInUi, type CasePlatform } from "@/lib/catalog";
import { cn } from "@/lib/utils";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { Cloud, Pencil, Plus, Trash2, Zap } from "lucide-react";
import { useMemo, useRef } from "react";
import {
  formatAddedDate,
  providerConnectionStatus,
  providerDisplayName,
  shortPlatformLabel,
  type ProviderConnectionStatus,
} from "./types";

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
  const rows = useMemo(
    () => connections.filter((conn) => isPlatformVisibleInUi(conn.platform)),
    [connections],
  );

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
    { scope: tableRef, dependencies: [rows.length], revertOnUpdate: true },
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
              {rows.map((conn) => {
                const status = providerConnectionStatus(conn);
                const displayName = providerDisplayName(conn);

                return (
                  <tr
                    key={conn.id}
                    className="provider-row border-b border-border/60 last:border-0 transition-colors hover:bg-surface-2/30"
                  >
                    <td className="table-cell font-medium">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-fg">{displayName}</p>
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
  );
}
