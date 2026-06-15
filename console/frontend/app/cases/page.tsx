"use client";

import { IntegrityBadge } from "@/components/badges";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { ImportDialog } from "@/components/import-dialog";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { api, deleteCase } from "@/lib/api";
import { CLOUDS, CLOUD_LABELS, type Cloud } from "@/lib/catalog";
import type { CaseSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Anchor, FolderOpen, ShieldAlert, Trash2, Upload } from "lucide-react";
import Link from "next/link";
import { useState, type ReactNode } from "react";

type Tab = "all" | Cloud;

export default function CasesPage() {
  const [importOpen, setImportOpen] = useState(false);
  const [tab, setTab] = useState<Tab>("all");
  const cases = useQuery({ queryKey: ["cases"], queryFn: api.cases });

  const all = cases.data?.cases ?? [];
  const countFor = (c: Tab) => (c === "all" ? all.length : all.filter((x) => x.cloud === c).length);
  const visible = tab === "all" ? all : all.filter((c) => c.cloud === tab);

  const tabs: { id: Tab; label: string }[] = [
    { id: "all", label: "All" },
    ...CLOUDS.map((c) => ({ id: c as Tab, label: CLOUD_LABELS[c] })),
  ];

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Anchor className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">Ventra</h1>
              <p className="text-xs text-fg-subtle">Cloud Incident Response Console</p>
            </div>
          </div>
          <Button variant="primary-dark" icon={Upload} onClick={() => setImportOpen(true)}>
              Import package
            </Button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        <div className="mb-4">
          <h2 className="text-base font-semibold">Cases</h2>
          <p className="text-sm text-fg-subtle">
            Each imported evidence package is a case. Browse by cloud, then open one to investigate.
          </p>
        </div>

        {/* Cloud division: AWS / Azure / GCP */}
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
                {t.id !== "all" && <CloudProviderIcon cloud={t.id} size={20} />}
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
              cloud={tab as Cloud}
              title={`No ${CLOUD_LABELS[tab as Cloud]} cases`}
              description={
                tab === "aws"
                  ? "Import an AWS evidence package collected with Ventra to begin."
                  : `The ${CLOUD_LABELS[tab as Cloud]} collector is on the roadmap. Cases will appear here once ${CLOUD_LABELS[tab as Cloud]} packages are imported.`
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
      </main>

      <ImportDialog open={importOpen} onClose={() => setImportOpen(false)} />
    </div>
  );
}

const CLOUD_BADGE: Record<string, string> = {
  aws: "border-border bg-surface-2",
  azure: "border-border bg-surface-2",
  gcp: "border-border bg-surface-2",
};

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

  return (
    <Link href={`/cases/${encodeURIComponent(c.case_id)}/overview`}>
      <Card className="group relative p-3 transition-colors hover:border-accent/40">
        <div className="flex items-center justify-between gap-3">
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
            <span
              className={cn(
                "mt-1.5 inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5",
                CLOUD_BADGE[c.cloud] ?? "border-border bg-surface-2",
              )}
            >
              <CloudProviderIcon cloud={c.cloud} size={16} />
              <span className="text-2xs font-medium uppercase text-fg-subtle">{c.cloud}</span>
            </span>
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
            className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 rounded-[inherit] bg-surface/95 px-4 text-center backdrop-blur-sm"
          >
            <p className="text-sm text-fg">
              Delete <span className="mono font-semibold">{c.case_id}</span> and all its evidence?
            </p>
            {del.error && (
              <p className="text-xs text-bad-red">{(del.error as Error).message}</p>
            )}
            <div className="flex items-center gap-2">
              <Button variant="ghost" onClick={(e) => { stop(e); setConfirming(false); }}>
                Cancel
              </Button>
              <Button
                variant="danger"
                icon={Trash2}
                loading={del.isPending}
                disabled={del.isPending}
                onClick={(e) => { stop(e); del.mutate(); }}
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
  cloud: Cloud;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <CloudProviderIcon cloud={cloud} size={48} />
      <div>
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        <p className="mt-1 max-w-md text-sm text-fg-subtle">{description}</p>
      </div>
      {action}
    </div>
  );
}

