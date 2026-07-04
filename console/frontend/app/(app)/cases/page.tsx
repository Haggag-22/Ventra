"use client";

import { IntegrityBadge } from "@/components/badges";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { ImportDialog } from "@/components/import-dialog";
import { S3ImportDialog } from "@/components/s3-import-dialog";
import { clearKitHandoff } from "@/lib/acquire-handoff";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { api, deleteCase } from "@/lib/api";
import { CASE_PLATFORM_LABELS, CASE_PLATFORMS, type CasePlatform } from "@/lib/catalog";
import { caseHref, caseReadinessPct, RUNS_NEW_HREF } from "@/lib/routes";
import type { CaseSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CloudDownload, FolderOpen, Play, ShieldAlert, Trash2, Upload } from "lucide-react";
import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";

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
    <div className="px-6 py-8">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="page-title">Cases</h1>
          <p className="page-subtitle">
            Each imported evidence package is a case. Browse by cloud, then open one to investigate.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href={RUNS_NEW_HREF}>
            <Button variant="secondary" icon={Play}>
              Run collection
            </Button>
          </Link>
          <Button variant="secondary" icon={CloudDownload} onClick={() => setS3ImportOpen(true)}>
            Import from S3
          </Button>
          <Button variant="primary-dark" icon={Upload} onClick={() => setImportOpen(true)}>
            Import package
          </Button>
        </div>
      </div>

      {!cases.isLoading && !cases.error && all.length > 0 && (
        <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <StatPill label="Total cases" value={all.length} />
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

      <div className="mb-6 flex items-center gap-1 border-b border-border">
          {tabs.map((t) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cn(
                  "relative -mb-px flex items-center gap-2 px-4 py-2.5 text-sm transition-colors",
                  active ? "text-fg" : "text-fg-subtle hover:text-fg",
                )}
              >
                {t.id !== "all" && <CloudProviderIcon cloud={t.id} />}
                {t.label}
                <span
                  className={cn(
                    "mono rounded-full px-1.5 py-0.5 text-2xs",
                    active ? "bg-accent/15 text-accent" : "bg-surface-2 text-fg-subtle",
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
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {visible.map((c) => (
              <CaseCard key={c.case_id} c={c} />
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
                  <Button variant="primary-dark" icon={Upload} onClick={() => setImportOpen(true)}>
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
                <Button variant="primary-dark" icon={Upload} onClick={() => setImportOpen(true)}>
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
}: {
  label: string;
  value: number;
  icon?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2.5">
      <div className="flex items-center gap-2 text-2xs text-fg-subtle">
        {icon}
        {label}
      </div>
      <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

function CaseCard({ c }: { c: CaseSummary }) {
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

  const readiness = caseReadinessPct(c);

  return (
    <Link href={caseHref(c.case_id, "overview")} className="block">
      <Card
        className={cn(
          "group relative p-3 transition-colors hover:border-accent/40",
          confirming && "min-h-[11.5rem]",
        )}
      >
        <div className={cn("flex items-center justify-between gap-3", confirming && "invisible")}>
          <div className="min-w-0">
            <div className="flex min-w-0 items-baseline gap-2">
              <span className="mono truncate text-sm font-semibold text-fg">{c.case_id}</span>
              {c.account_id && (
                <>
                  <span className="shrink-0 text-fg-subtle/60">·</span>
                  <span className="mono truncate text-xs text-fg-subtle">{c.account_id}</span>
                </>
              )}
            </div>
            <span className="mt-1.5 inline-flex items-center gap-1.5">
              <CloudProviderIcon cloud={c.cloud} />
              <span className="text-2xs font-medium uppercase text-fg-subtle">{c.cloud}</span>
            </span>
            {readiness != null && (
              <span className="mt-1.5 block text-2xs text-fg-subtle">
                <span className="font-medium text-ok-green">{readiness}%</span> collection ready
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <IntegrityBadge value={c.integrity} showLabel={false} />
            <button
              type="button"
              aria-label="Delete case"
              onClick={(e) => {
                stop(e);
                setConfirming(true);
              }}
              className="rounded p-1 text-fg-subtle opacity-0 transition-opacity hover:bg-bad-red/10 hover:text-bad-red group-hover:opacity-100"
            >
              <Trash2 className="h-4 w-4" />
            </button>
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

