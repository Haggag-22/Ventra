"use client";

import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { ImportDialog } from "@/components/import-dialog";
import { S3ImportDialog } from "@/components/s3-import-dialog";
import { clearKitHandoff } from "@/lib/acquire-handoff";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { api, deleteCase, listConnections, listRuns } from "@/lib/api";
import { CASE_PLATFORM_LABELS, CASE_PLATFORMS, type CasePlatform } from "@/lib/catalog";
import { fmtBytes, fmtDateOnly, fmtNum } from "@/lib/format";
import { caseHref, acquireRunHref } from "@/lib/routes";
import { readLastConnection } from "@/lib/provider-storage";
import type { CaseSummary, RunMeta } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CloudDownload,
  Clock,
  Database,
  FolderOpen,
  HardDrive,
  KeyRound,
  Play,
  ShieldAlert,
  Trash2,
  Upload,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState, type ReactNode } from "react";

type Tab = "all" | CasePlatform;

function readImportCaseParam(): string {
  if (typeof window === "undefined") return "";
  return new URLSearchParams(window.location.search).get("import_case")?.trim() || "";
}

function readImportS3Param(): boolean {
  if (typeof window === "undefined") return false;
  return new URLSearchParams(window.location.search).get("import_s3") === "1";
}

export default function CasesPage() {
  const [importOpen, setImportOpen] = useState(false);
  const [s3ImportOpen, setS3ImportOpen] = useState(false);
  const [importCaseId, setImportCaseId] = useState("");
  const [tab, setTab] = useState<Tab>("all");
  const cases = useQuery({ queryKey: ["cases"], queryFn: api.cases });
  const connections = useQuery({
    queryKey: ["config", "connections"],
    queryFn: listConnections,
    staleTime: 60_000,
  });
  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: listRuns,
    staleTime: 30_000,
  });

  const authByCaseId = useMemo(
    () => buildCaseAuthNames(cases.data?.cases ?? [], connections.data?.connections ?? [], runs.data?.runs ?? []),
    [cases.data, connections.data, runs.data],
  );

  useEffect(() => {
    const id = readImportCaseParam();
    if (id) {
      setImportCaseId(id);
      setImportOpen(true);
    }
    if (readImportS3Param()) {
      setS3ImportOpen(true);
    }
  }, []);

  const all = cases.data?.cases ?? [];
  const countFor = (c: Tab) => (c === "all" ? all.length : all.filter((x) => x.cloud === c).length);
  const visible = tab === "all" ? all : all.filter((c) => c.cloud === tab);

  const tabs: { id: Tab; label: string }[] = [
    { id: "all", label: "All" },
    ...CASE_PLATFORMS.map((c) => ({ id: c as Tab, label: CASE_PLATFORM_LABELS[c] })),
  ];

  return (
    <div className="px-6 py-7">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-border/70 pb-5">
        <div>
          <h1 className="page-title">
            <FolderOpen className="h-5 w-5 text-accent" />
            Cases
          </h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link href={acquireRunHref(readLastConnection())}>
            <Button variant="secondary" icon={Play}>
              Run collection
            </Button>
          </Link>
          <Button variant="secondary" icon={CloudDownload} onClick={() => setS3ImportOpen(true)}>
            Import from S3
          </Button>
          <Button variant="primary" icon={Upload} onClick={() => setImportOpen(true)}>
            Import package
          </Button>
        </div>
      </div>

      {!cases.isLoading && !cases.error && all.length > 0 && (
        <div className="mb-5 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          <StatPill label="Total cases" value={all.length} tone="accent" />
          {CASE_PLATFORMS.map((platform) => (
            <StatPill
              key={platform}
              label={CASE_PLATFORM_LABELS[platform]}
              value={countFor(platform as Tab)}
              icon={<CloudProviderIcon cloud={platform} />}
            />
          ))}
        </div>
      )}

      <div className="mb-5 flex items-center gap-1 overflow-x-auto border-b border-border/80">
          {tabs.map((t) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cn(
                  "relative -mb-px flex h-10 items-center gap-2 whitespace-nowrap px-3 text-sm font-medium transition-colors",
                  active ? "text-fg" : "text-fg-subtle hover:text-fg",
                )}
              >
                {t.id !== "all" && <CloudProviderIcon cloud={t.id} />}
                {t.label}
                <span
                  className={cn(
                    "mono rounded-full px-1.5 py-0.5 text-2xs",
                    active ? "bg-accent/15 text-accent" : "bg-surface text-fg-subtle",
                  )}
                >
                  {countFor(t.id)}
                </span>
                {active && <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-accent" />}
              </button>
            );
          })}
        </div>

        {cases.isLoading ? (
          <LoadingPanel label="Loading cases…" />
        ) : cases.error ? (
          <Card className="p-6">
            <EmptyState
              icon={ShieldAlert}
              title="Can't reach the backend"
              description={
                <>
                  The console API isn&apos;t responding. Start it with{" "}
                  <code className="mono rounded bg-surface-2 px-1">ventra-console</code> or via the
                  Docker Compose stack, then reload.
                </>
              }
            />
          </Card>
        ) : visible.length > 0 ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            {visible.map((c) => (
              <CaseCard key={c.case_id} c={c} authName={authByCaseId.get(c.case_id)} />
            ))}
          </div>
        ) : tab !== "all" ? (
          <Card className="py-4">
            <CloudTabEmpty
              cloud={tab}
              title={`No ${CASE_PLATFORM_LABELS[tab]} cases`}
              description={
                tab === "aws"
                  ? "Import an AWS evidence package collected with Ventra to begin."
                  : tab === "kubernetes"
                    ? "Standalone Kubernetes evidence packages are coming soon. Cases will appear here once in-cluster collection is available."
                    : `The ${CASE_PLATFORM_LABELS[tab]} collector is on the roadmap. Cases will appear here once ${CASE_PLATFORM_LABELS[tab]} packages are imported.`
              }
              action={
                tab === "aws" ? (
                  <Button variant="primary" icon={Upload} onClick={() => setImportOpen(true)}>
                    Import package
                  </Button>
                ) : undefined
              }
            />
          </Card>
        ) : (
          <Card className="py-4">
            <EmptyState
              icon={FolderOpen}
              title="No cases yet"
              description="Import a Ventra evidence package to begin. Ventra verifies its integrity, normalizes every source, and opens it for investigation."
              action={
                <Button variant="primary" icon={Upload} onClick={() => setImportOpen(true)}>
                  Import package
                </Button>
              }
            />
          </Card>
        )}
      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        defaultCaseId={importCaseId}
        onImported={(caseId) => clearKitHandoff(caseId)}
      />
      <S3ImportDialog open={s3ImportOpen} onClose={() => setS3ImportOpen(false)} />
    </div>
  );
}

function StatPill({
  label,
  value,
  icon,
  tone = "default",
}: {
  label: string;
  value: number;
  icon?: ReactNode;
  tone?: "default" | "accent";
}) {
  return (
    <div
      className={cn(
        "rounded-md border bg-surface px-3 py-2.5",
        tone === "accent" ? "border-accent/35" : "border-border",
      )}
    >
      <div className="stat-card-header text-2xs font-medium uppercase tracking-wide text-fg-subtle">
        {icon ? <span className="inline-flex shrink-0 items-center">{icon}</span> : null}
        <span className="min-w-0 truncate">{label}</span>
      </div>
      <div className="mt-1 text-xl font-semibold tabular-nums">{fmtNum(value)}</div>
    </div>
  );
}

function runTimestamp(run: RunMeta): number {
  const raw = run.started_at ?? run.created_at;
  if (!raw) return 0;
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : 0;
}

function buildCaseAuthNames(
  caseSummaries: CaseSummary[],
  connections: { id: string; name: string }[],
  runs: RunMeta[],
): Map<string, string> {
  const connectionNames = new Map(connections.map((c) => [c.id, c.name]));
  const byCase = new Map<string, { name: string; ts: number }>();

  for (const run of runs) {
    if (!run.case_id || !run.connection_id) continue;
    const name = connectionNames.get(run.connection_id);
    if (!name) continue;
    const ts = runTimestamp(run);
    const prev = byCase.get(run.case_id);
    if (!prev || ts >= prev.ts) {
      byCase.set(run.case_id, { name, ts });
    }
  }

  const out = new Map<string, string>();
  for (const c of caseSummaries) {
    const linked = byCase.get(c.case_id)?.name;
    const profile = c.profile?.name?.trim();
    out.set(c.case_id, linked ?? profile ?? "No authentication");
  }
  return out;
}

function formatCaseTimeRange(c: CaseSummary): string {
  const tw = c.time_window;
  if (tw?.since || tw?.until) {
    const since = tw.since ? fmtDateOnly(tw.since) : "start";
    const until = tw.until ? fmtDateOnly(tw.until) : "now";
    return `${since} → ${until}`;
  }
  const first = c.event_span?.first;
  const last = c.event_span?.last;
  if (first || last) {
    const start = first ? fmtDateOnly(first) : "—";
    const end = last ? fmtDateOnly(last) : "—";
    return `${start} → ${end}`;
  }
  if (tw?.mode === "full_available") return "Full available";
  return "—";
}

function formatCaseStorage(c: CaseSummary): string {
  const bytes = c.storage_bytes;
  if (bytes != null && bytes > 0) return fmtBytes(bytes);
  return "—";
}

function CaseCard({ c, authName }: { c: CaseSummary; authName?: string }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const del = useMutation({
    mutationFn: () => deleteCase(c.case_id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cases"] }),
  });

  const stop = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const authentication = authName ?? "No authentication";
  const timeRange = formatCaseTimeRange(c);
  const storage = formatCaseStorage(c);

  return (
    <Link href={caseHref(c.case_id, "overview")} className="block">
      <Card
        className={cn(
          "group relative overflow-hidden p-0 transition-colors hover:border-accent/45",
          confirming && "min-h-[9rem]",
        )}
      >
        <div className={cn("p-4", confirming && "invisible")}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex min-w-0 items-center gap-2">
                <CloudProviderIcon cloud={c.cloud} />
                <span className="mono truncate text-sm font-semibold text-fg">{c.case_id}</span>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                type="button"
                aria-label="Delete case"
                onClick={(e) => {
                  stop(e);
                  setConfirming(true);
                }}
                className="rounded-md border border-transparent p-1 text-fg-subtle opacity-0 transition-opacity hover:border-bad-red/25 hover:bg-bad-red/10 hover:text-bad-red group-hover:opacity-100"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>

          <div className="mt-3">
            <CaseMetric
              icon={KeyRound}
              label="Authentication"
              value={authentication}
              tone={authentication === "No authentication" ? "muted" : "default"}
            />
          </div>

          <div className="mt-2">
            <CaseMetric icon={Clock} label="Time range" value={timeRange} />
          </div>

          <div className="mt-2 grid grid-cols-2 gap-2">
            <CaseMetric icon={Database} label="Events" value={fmtNum(c.totals?.events)} />
            <CaseMetric icon={HardDrive} label="Size" value={storage} />
          </div>
        </div>

        {confirming && (
          <div
            onClick={stop}
            className="absolute inset-0 z-10 flex flex-col rounded-[inherit] bg-surface/95 p-4 backdrop-blur-sm"
          >
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto text-center">
              <p className="text-sm text-fg">Delete this case and all its evidence?</p>
              <p className="rounded border border-border bg-surface-2 px-2 py-1.5 mono text-2xs font-semibold leading-relaxed text-fg break-all">
                {c.case_id}
              </p>
              {del.error && (
                <p className="text-xs text-bad-red">{(del.error as Error).message}</p>
              )}
            </div>
            <div className="mt-3 flex shrink-0 items-center justify-end gap-2 border-t border-border/50 pt-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={(e) => {
                  stop(e);
                  setConfirming(false);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                size="sm"
                icon={Trash2}
                loading={del.isPending}
                disabled={del.isPending}
                onClick={(e) => {
                  stop(e);
                  del.mutate();
                }}
              >
                {del.isPending ? "Deleting…" : "Delete"}
              </Button>
            </div>
          </div>
        )}
      </Card>
    </Link>
  );
}

function CaseMetric({
  icon: Icon,
  label,
  value,
  tone = "default",
}: {
  icon: typeof Database;
  label: string;
  value: string;
  tone?: "default" | "danger" | "warning" | "success" | "muted";
}) {
  const toneClass =
    tone === "danger"
      ? "text-bad-red"
      : tone === "warning"
        ? "text-warn-amber"
        : tone === "success"
          ? "text-ok-green"
          : tone === "muted"
            ? "text-fg-subtle"
            : "text-fg";

  return (
    <div className="rounded-md border border-border/75 bg-bg/35 px-2.5 py-2">
      <div className="flex items-center gap-1.5 text-2xs font-medium uppercase tracking-wide text-fg-subtle">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div
        className={cn(
          "mt-1 truncate text-sm font-semibold",
          label === "Authentication" ? "" : "mono tabular-nums",
          toneClass,
        )}
        title={value}
      >
        {value}
      </div>
    </div>
  );
}

function CloudTabEmpty({
  cloud,
  title,
  description,
  action,
}: {
  cloud: CasePlatform;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <CloudProviderIcon cloud={cloud} />
      <div>
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        <p className="mt-1 max-w-md text-sm text-fg-subtle">{description}</p>
      </div>
      {action}
    </div>
  );
}
