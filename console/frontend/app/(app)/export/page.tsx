"use client";

import { ArtifactIcon } from "@/components/artifact-icon";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Button, Card, EmptyState, LoadingPanel } from "@/components/ui";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { exportCasesBatch, ExportCancelledError, listExportableCases } from "@/lib/api";
import { fmtBytes, fmtDateOnly, fmtNum } from "@/lib/format";
import type { ExportableCase, ExportTarget } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertCircle,
  Boxes,
  Check,
  Database,
  Download,
  FolderOpen,
  Layers,
  ShieldAlert,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

const TARGETS: {
  id: ExportTarget;
  label: string;
  description: string;
  icon: LucideIcon;
}[] = [
  {
    id: "elastic",
    label: "Elastic",
    description: "ECS-shaped NDJSON plus a starting index template. Remap in your pipeline if needed.",
    icon: Boxes,
  },
  {
    id: "splunk",
    label: "Splunk",
    description: "CIM-normalized HEC NDJSON — replay to HEC or load via a forwarder. Remap if needed.",
    icon: Layers,
  },
  {
    id: "ndjson",
    label: "Generic NDJSON",
    description: "Unshaped normalized events, one per line.",
    icon: Database,
  },
];

function formatCaseDateRange(c: ExportableCase): string {
  const { first, last } = c.date_range;
  if (!first && !last) return "—";
  return `${first ? fmtDateOnly(first) : "—"} → ${last ? fmtDateOnly(last) : "—"}`;
}

function formatCaseStorage(bytes: number | null | undefined): string {
  if (bytes != null && bytes > 0) return fmtBytes(bytes);
  return "—";
}

/** Event count for a source across selected cases. */
function sourceEventCount(source: string, cases: ExportableCase[]): number {
  let total = 0;
  for (const c of cases) {
    total += c.by_source?.[source] ?? 0;
  }
  return total;
}

/** Approximate on-disk share of a source across selected cases (events × case storage). */
function estimateSourceBytes(source: string, cases: ExportableCase[]): number | null {
  let total = 0;
  let any = false;
  for (const c of cases) {
    const count = c.by_source?.[source] ?? 0;
    const events = c.event_count || 0;
    const storage = c.storage_bytes ?? 0;
    if (count > 0 && events > 0 && storage > 0) {
      total += Math.round((count / events) * storage);
      any = true;
    }
  }
  return any ? total : null;
}

export default function ExportPage() {
  const cases = useQuery({ queryKey: ["cases", "exportable"], queryFn: listExportableCases });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [target, setTarget] = useState<ExportTarget>("elastic");
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const [cancelledMsg, setCancelledMsg] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const all = useMemo(() => cases.data?.cases ?? [], [cases.data]);

  const selectedCase = useMemo(
    () => (selectedId ? all.find((c) => c.case_id === selectedId) ?? null : null),
    [all, selectedId],
  );
  const selectedCases = useMemo(
    () => (selectedCase ? [selectedCase] : []),
    [selectedCase],
  );
  const totalEvents = selectedCase?.event_count ?? 0;
  const totalBytes = selectedCase?.storage_bytes ?? 0;
  const scopeCloud = selectedCase ? selectedCase.cloud.toLowerCase() : null;

  const availableSources = useMemo(() => {
    if (!selectedCase) return [];
    return [...selectedCase.sources].sort((a, b) =>
      displayArtifactLabel(a).localeCompare(displayArtifactLabel(b)),
    );
  }, [selectedCase]);

  // Drop source picks that no longer apply when the case selection changes.
  useEffect(() => {
    setSourceFilter((prev) => {
      if (prev.size === 0) return prev;
      if (!selectedCase) return new Set();
      const valid = new Set(availableSources);
      const next = new Set([...prev].filter((s) => valid.has(s)));
      return next.size === prev.size ? prev : next;
    });
  }, [selectedCase, availableSources]);

  const exportMut = useMutation({
    mutationFn: async () => {
      if (!selectedId) throw new Error("Select a case to export");
      const ac = new AbortController();
      abortRef.current = ac;
      try {
        await exportCasesBatch({
          case_ids: [selectedId],
          target,
          sources: sourceFilter.size ? [...sourceFilter] : undefined,
          signal: ac.signal,
        });
      } finally {
        abortRef.current = null;
      }
    },
    onMutate: () => {
      setError("");
      setDone(false);
      setCancelledMsg(false);
    },
    onSuccess: () => setDone(true),
    onError: (e: unknown) => {
      if (e instanceof ExportCancelledError) {
        setCancelledMsg(true);
        setError("");
        return;
      }
      setError(e instanceof Error ? e.message : "Export failed");
    },
  });

  const exporting = exportMut.isPending;

  const selectCase = (id: string) => {
    if (exporting) return;
    setSelectedId((prev) => (prev === id ? null : id));
    setSourceFilter(new Set());
  };

  const toggleSource = (s: string) => {
    if (exporting) return;
    setSourceFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const allSourcesSelected =
    availableSources.length > 0 && availableSources.every((s) => sourceFilter.has(s));

  const toggleAllSources = () => {
    if (exporting) return;
    if (allSourcesSelected) setSourceFilter(new Set());
    else setSourceFilter(new Set(availableSources));
  };

  const cancelExport = () => {
    abortRef.current?.abort();
  };

  const canExport = Boolean(selectedId) && !exporting;
  const showScope = Boolean(selectedCase);

  return (
    <div className="px-6 py-7">
      <div className="mb-6 border-b border-border/70 pb-5">
        <h1 className="page-title">
          <Download className="h-5 w-5 text-accent" />
          Export
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-fg-subtle">
          Download case events as NDJSON for your SIEM. Load the zip with Logstash or your
          forwarder.
        </p>
      </div>

      {cases.isLoading ? (
        <LoadingPanel label="Loading cases…" />
      ) : cases.error ? (
        <Card className="p-6">
          <EmptyState
            icon={ShieldAlert}
            title="Can't reach the backend"
            description="The console API isn't responding. Start it with ventra-console, then reload."
          />
        </Card>
      ) : all.length === 0 ? (
        <Card className="py-4">
          <EmptyState
            icon={FolderOpen}
            title="No cases yet"
            description="Import a Ventra evidence package before you can export it."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_22rem]">
          <div
            className={cn("space-y-5", exporting && "pointer-events-none select-none opacity-55")}
            aria-busy={exporting}
          >
            <Card className="overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full table-fixed text-left text-sm">
                  <colgroup>
                    <col className="w-10" />
                    <col />
                    <col className="w-64" />
                    <col className="w-52" />
                    <col className="w-44" />
                  </colgroup>
                  <thead>
                    <tr className="table-head-row">
                      <th className="table-header-cell-center w-10" aria-label="Select" />
                      <th className="table-header-cell">Case</th>
                      <th className="table-header-cell !px-12">Time range</th>
                      <th className="table-header-cell-right !px-12">Events</th>
                      <th className="table-header-cell-right !px-12">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {all.map((c) => {
                      const isSelected = selectedId === c.case_id;
                      return (
                        <tr
                          key={c.case_id}
                          className={cn(
                            "border-b border-border/50 transition-colors",
                            exporting
                              ? "cursor-not-allowed"
                              : "cursor-pointer hover:bg-surface-2/30",
                            isSelected && "bg-accent/5",
                          )}
                          onClick={() => selectCase(c.case_id)}
                        >
                          <td className="table-cell-center">
                            <span
                              className={cn(
                                "mx-auto flex h-4 w-4 items-center justify-center rounded-full border",
                                isSelected
                                  ? "border-accent bg-accent text-accent-fg"
                                  : "border-border bg-surface-2",
                              )}
                              aria-checked={isSelected}
                              role="radio"
                            >
                              {isSelected && <span className="h-1.5 w-1.5 rounded-full bg-accent-fg" />}
                            </span>
                          </td>
                          <td className="table-cell">
                            <div className="flex min-w-0 items-center gap-2.5">
                              <CloudProviderIcon cloud={c.cloud} />
                              <span className="mono truncate font-medium text-fg">{c.case_id}</span>
                            </div>
                          </td>
                          <td className="table-cell-muted mono whitespace-nowrap !px-12">
                            {formatCaseDateRange(c)}
                          </td>
                          <td className="table-cell-muted !px-12 !text-right mono">
                            {fmtNum(c.event_count)}
                          </td>
                          <td className="table-cell-muted !px-12 !text-right mono">
                            {formatCaseStorage(c.storage_bytes)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>

            {showScope && (
              <Card className="overflow-hidden">
                {availableSources.length === 0 ? (
                  <p className="px-4 py-6 text-xs text-fg-subtle">
                    No sources available for the selected case.
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full table-fixed text-left text-sm">
                      <colgroup>
                        <col className="w-10" />
                        <col />
                        <col className="w-52" />
                        <col className="w-44" />
                      </colgroup>
                      <thead>
                        <tr className="table-head-row">
                          <th className="table-header-cell-center w-10">
                            <button
                              type="button"
                              aria-label={allSourcesSelected ? "Deselect all sources" : "Select all sources"}
                              className="mx-auto flex h-4 w-4 items-center justify-center"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleAllSources();
                              }}
                            >
                              <span
                                className={cn(
                                  "flex h-4 w-4 items-center justify-center rounded border",
                                  allSourcesSelected
                                    ? "border-accent bg-accent text-accent-fg"
                                    : "border-border bg-surface-2",
                                )}
                              >
                                {allSourcesSelected && <Check className="h-3 w-3" />}
                              </span>
                            </button>
                          </th>
                          <th className="table-header-cell">Source</th>
                          <th className="table-header-cell-right !px-12">Events</th>
                          <th className="table-header-cell-right !px-12">Size</th>
                        </tr>
                      </thead>
                      <tbody>
                        {availableSources.map((s) => {
                          const active = sourceFilter.has(s);
                          const events = sourceEventCount(s, selectedCases);
                          const sizeBytes = estimateSourceBytes(s, selectedCases);
                          return (
                            <tr
                              key={s}
                              className={cn(
                                "cursor-pointer border-b border-border/50 transition-colors hover:bg-surface-2/30",
                                active && "bg-accent/5",
                              )}
                              onClick={() => toggleSource(s)}
                            >
                              <td className="table-cell-center">
                                <span
                                  className={cn(
                                    "mx-auto flex h-4 w-4 items-center justify-center rounded border",
                                    active
                                      ? "border-accent bg-accent text-accent-fg"
                                      : "border-border bg-surface-2",
                                  )}
                                >
                                  {active && <Check className="h-3 w-3" />}
                                </span>
                              </td>
                              <td className="table-cell">
                                <div className="flex min-w-0 items-center gap-2.5">
                                  <ArtifactIcon cloud={scopeCloud!} collector={s} size={24} />
                                  <span className="truncate text-sm font-medium text-fg">
                                    {displayArtifactLabel(s)}
                                  </span>
                                </div>
                              </td>
                              <td className="table-cell-muted !px-12 !text-right mono">
                                {fmtNum(events)}
                              </td>
                              <td className="table-cell-muted !px-12 !text-right mono">
                                {formatCaseStorage(sizeBytes)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            )}
          </div>

          <div className="space-y-5 lg:sticky lg:top-6 lg:self-start">
            <Card className="p-4">
              <h2 className="mb-3 text-sm font-semibold text-fg">Summary</h2>
              <dl className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <dt className="text-fg-subtle">Case</dt>
                  <dd className="mono max-w-[12rem] truncate font-medium text-fg">
                    {selectedCase?.case_id ?? "—"}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-fg-subtle">Events (approx.)</dt>
                  <dd className="mono font-medium text-fg">{fmtNum(totalEvents)}</dd>
                </div>
                {selectedCase && (
                  <div className="flex items-center justify-between">
                    <dt className="text-fg-subtle">Size</dt>
                    <dd className="mono font-medium text-fg">{formatCaseStorage(totalBytes)}</dd>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <dt className="text-fg-subtle">Target</dt>
                  <dd className="font-medium text-fg">
                    {TARGETS.find((t) => t.id === target)?.label}
                  </dd>
                </div>
                {sourceFilter.size > 0 && (
                  <div className="flex items-center justify-between">
                    <dt className="text-fg-subtle">Sources</dt>
                    <dd className="mono font-medium text-fg">{sourceFilter.size}</dd>
                  </div>
                )}
              </dl>

              <div className="mt-4 border-t border-border/70 pt-4">
                <h3 className="mb-2 text-2xs font-medium uppercase tracking-wide text-fg-subtle">
                  Target
                </h3>
                <div className="space-y-2">
                  {TARGETS.map((t) => {
                    const Icon = t.icon;
                    const isActive = target === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        disabled={exporting}
                        onClick={() => setTarget(t.id)}
                        className={cn(
                          "acquire-collector-row flex w-full items-start gap-2.5 p-2.5 text-left",
                          isActive && "is-selected",
                          exporting && "cursor-not-allowed opacity-55",
                        )}
                      >
                        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle" />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-sm font-medium text-fg">{t.label}</span>
                            {isActive && <Check className="h-3.5 w-3.5 shrink-0 text-accent" />}
                          </div>
                          <span className="mt-0.5 block text-2xs leading-relaxed text-fg-subtle">
                            {t.description}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {error && (
                <div className="mt-3 flex items-start gap-2 rounded-md border border-bad-red/30 bg-bad-red/10 p-2.5 text-xs text-bad-red">
                  <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              {exporting && (
                <p className="mt-3 text-xs text-fg-subtle">
                  Export in progress — case and source selection are locked until it finishes
                  or you cancel.
                </p>
              )}
              {cancelledMsg && !error && !exporting && (
                <p className="mt-3 text-xs text-fg-subtle">Export cancelled.</p>
              )}
              {done && !error && !exporting && (
                <p className="mt-3 text-xs text-ok-green">Export downloaded.</p>
              )}

              {exporting ? (
                <div className="mt-4 flex flex-col gap-2">
                  <Button
                    variant="primary"
                    icon={Download}
                    className="w-full justify-center"
                    loading
                    disabled
                  >
                    Preparing export…
                  </Button>
                  <Button
                    variant="danger"
                    icon={X}
                    className="w-full justify-center"
                    onClick={cancelExport}
                  >
                    Cancel export
                  </Button>
                </div>
              ) : (
                <Button
                  variant="primary"
                  icon={Download}
                  className="mt-4 w-full justify-center"
                  disabled={!canExport}
                  onClick={() => exportMut.mutate()}
                >
                  {selectedId == null ? "Select a case" : "Download export"}
                </Button>
              )}
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
