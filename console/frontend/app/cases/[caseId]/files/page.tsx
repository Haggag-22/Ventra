"use client";

import { ArtifactIcon } from "@/components/artifact-icon";
import { useCase } from "@/components/case-context";
import { PanelBody, PanelHeader } from "@/components/panel";
import { Button, Card, EmptyState, Input, LoadingPanel } from "@/components/ui";
import { api } from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { caseCloud } from "@/lib/cloud-sources";
import { fmtBytes, fmtNum } from "@/lib/format";
import { panelLabel } from "@/lib/panel-labels";
import type { EvidenceFileEntry } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  Braces,
  ChevronDown,
  Download,
  File,
  FileJson,
  FileText,
  FolderOpen,
  Search,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

interface CollectorGroup {
  id: string;
  label: string;
  files: EvidenceFileEntry[];
}

function fileIcon(kind: string) {
  if (kind === "events") return FileText;
  if (kind === "config" || kind === "snapshot" || kind === "meta" || kind === "manifest") {
    return FileJson;
  }
  return File;
}

function groupByCollector(files: EvidenceFileEntry[]): CollectorGroup[] {
  const groups = new Map<string, EvidenceFileEntry[]>();
  for (const f of files) {
    let id = "package-root";
    if (f.path.startsWith("sources/")) {
      id = f.source || f.path.split("/")[1] || "unknown";
    } else if (f.path.startsWith("errors/")) {
      id = "errors";
    }
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id)!.push(f);
  }
  return [...groups.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([id, items]) => ({
      id,
      label:
        id === "package-root"
          ? "Package root"
          : id === "errors"
            ? "Collection errors"
            : displayArtifactLabel(id),
      files: items.sort((a, b) => a.path.localeCompare(b.path)),
    }));
}

function groupTotalBytes(files: EvidenceFileEntry[]): number {
  return files.reduce((sum, f) => sum + f.size, 0);
}

function groupRecordCount(files: EvidenceFileEntry[]): number {
  return files.reduce((sum, f) => sum + (f.record_count ?? 0), 0);
}

function JsonPreview({ value }: { value: unknown }) {
  return (
    <pre className="ct-json max-h-[min(70vh,900px)] overflow-auto rounded-md border border-border bg-surface-2 p-3 text-xs">
      <code>{JSON.stringify(value, null, 2)}</code>
    </pre>
  );
}

function TextPreview({ text, truncated }: { text: string; truncated: boolean }) {
  return (
    <>
      {truncated && (
        <p className="mb-2 text-xs text-warn-amber">
          Preview truncated — download the file for the full contents.
        </p>
      )}
      <pre className="max-h-[min(70vh,900px)] overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-xs text-fg">
        {text}
      </pre>
    </>
  );
}

function EventsPreview({ caseId, path }: { caseId: string; path: string }) {
  const [offset, setOffset] = useState(0);
  const [records, setRecords] = useState<unknown[]>([]);
  const [totalLines, setTotalLines] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(
    async (nextOffset: number, append: boolean) => {
      setLoading(true);
      setError("");
      try {
        const page = await api.evidenceLines(caseId, path, nextOffset, 500);
        setTotalLines(page.total_lines);
        setHasMore(page.has_more);
        setOffset(nextOffset + page.count);
        setRecords((prev) => (append ? [...prev, ...page.records] : page.records));
      } catch (e: any) {
        setError(e.message || "Failed to load records");
      } finally {
        setLoading(false);
      }
    },
    [caseId, path],
  );

  useEffect(() => {
    setRecords([]);
    setOffset(0);
    void load(0, false);
  }, [load]);

  return (
    <div className="space-y-3">
      <p className="text-xs text-fg-subtle">
        Showing {fmtNum(records.length)} of {fmtNum(totalLines)} line(s)
      </p>
      {error && <p className="text-xs text-bad-red">{error}</p>}
      <div className="max-h-[min(70vh,900px)] overflow-auto rounded-md border border-border">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-surface-2 text-2xs uppercase tracking-wide text-fg-subtle">
            <tr>
              <th className="px-3 py-2 w-12">#</th>
              <th className="px-3 py-2">Record</th>
            </tr>
          </thead>
          <tbody>
            {records.map((rec, i) => (
              <tr key={i} className="border-t border-border align-top">
                <td className="px-3 py-2 mono text-fg-subtle">{i + 1}</td>
                <td className="px-3 py-2">
                  <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-fg">
                    {JSON.stringify(rec, null, 2)}
                  </pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap gap-2">
        {hasMore && (
          <Button size="sm" variant="secondary" loading={loading} onClick={() => load(offset, true)}>
            Load more
          </Button>
        )}
        {hasMore && (
          <Button
            size="sm"
            variant="ghost"
            loading={loading}
            onClick={async () => {
              let next = offset;
              let more = true;
              let merged = [...records];
              while (more) {
                const page = await api.evidenceLines(caseId, path, next, 2000);
                merged = [...merged, ...page.records];
                next += page.count;
                more = page.has_more;
              }
              setRecords(merged);
              setOffset(next);
              setHasMore(false);
            }}
          >
            Load all remaining
          </Button>
        )}
      </div>
    </div>
  );
}

function FilePreview({ caseId, file }: { caseId: string; file: EvidenceFileEntry }) {
  const isEvents = file.kind === "events";
  const contentQ = useQuery({
    queryKey: ["evidence-content", caseId, file.path, isEvents],
    queryFn: () => api.evidenceContent(caseId, file.path),
    enabled: !isEvents,
  });

  if (isEvents) {
    return <EventsPreview caseId={caseId} path={file.path} />;
  }

  if (contentQ.isLoading) return <LoadingPanel label="Loading preview…" />;
  if (contentQ.error) {
    return (
      <EmptyState
        icon={File}
        title="Preview unavailable"
        description={(contentQ.error as Error).message}
      />
    );
  }

  const data = contentQ.data!;
  if (data.content_type === "json" && data.json !== undefined) {
    return <JsonPreview value={data.json} />;
  }
  return <TextPreview text={data.text || ""} truncated={data.truncated} />;
}

function CollectorSection({
  group,
  cloud,
  expanded,
  onToggle,
  selected,
  onSelect,
}: {
  group: CollectorGroup;
  cloud: string;
  expanded: boolean;
  onToggle: () => void;
  selected: EvidenceFileEntry | null;
  onSelect: (file: EvidenceFileEntry) => void;
}) {
  const records = groupRecordCount(group.files);
  const hasSelected = group.files.some((f) => f.path === selected?.path);

  return (
    <div
      className={cn(
        "overflow-hidden rounded-lg border border-border bg-surface",
        hasSelected && "border-accent/30",
      )}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className={cn(
          "flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors",
          expanded ? "bg-surface-2" : "hover:bg-surface-2/70",
        )}
      >
        <ChevronDown
          className={cn(
            "h-4 w-4 shrink-0 text-fg-subtle transition-transform",
            !expanded && "-rotate-90",
          )}
        />
        <ArtifactIcon cloud={cloud} collector={group.id} size={22} />
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">{group.label}</span>
        <span className="shrink-0 text-2xs text-fg-subtle">
          {group.files.length} file{group.files.length === 1 ? "" : "s"}
          {records > 0 ? ` · ${fmtNum(records)} rec` : ""}
          {" · "}
          {fmtBytes(groupTotalBytes(group.files))}
        </span>
      </button>
      {expanded && (
        <ul className="border-t border-border py-1">
          {group.files.map((file) => {
            const Icon = fileIcon(file.kind);
            const active = selected?.path === file.path;
            return (
              <li key={file.path}>
                <button
                  type="button"
                  onClick={() => onSelect(file)}
                  className={cn(
                    "flex w-full items-center gap-2 px-3 py-2 pl-10 text-left text-xs transition-colors",
                    active
                      ? "bg-accent/12 text-fg"
                      : "text-fg-subtle hover:bg-surface-2 hover:text-fg",
                  )}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium">{file.path.split("/").pop()}</span>
                    <span className="mono block truncate text-2xs text-fg-subtle">
                      {fmtBytes(file.size)}
                      {file.record_count != null ? ` · ${fmtNum(file.record_count)} records` : ""}
                      {file.kind ? ` · ${file.kind}` : ""}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

export default function FilesPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<EvidenceFileEntry | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const indexQ = useQuery({
    queryKey: ["evidence-index", caseId],
    queryFn: () => api.evidenceIndex(caseId),
  });

  const filtered = useMemo(() => {
    const files = indexQ.data?.files ?? [];
    const s = search.trim().toLowerCase();
    if (!s) return files;
    return files.filter(
      (f) =>
        f.path.toLowerCase().includes(s) ||
        (f.source || "").toLowerCase().includes(s) ||
        (f.kind || "").toLowerCase().includes(s),
    );
  }, [indexQ.data, search]);

  const groups = useMemo(() => groupByCollector(filtered), [filtered]);
  const searching = search.trim().length > 0;

  const toggleGroup = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const expandAll = useCallback(() => {
    setExpanded(new Set(groups.map((g) => g.id)));
  }, [groups]);

  const collapseAll = useCallback(() => {
    setExpanded(new Set());
  }, []);

  useEffect(() => {
    if (!indexQ.data?.files.length) return;
    if (!selected) {
      setSelected(indexQ.data.files[0]!);
    }
  }, [indexQ.data, selected]);

  useEffect(() => {
    if (groups.length === 0) return;
    if (searching) {
      setExpanded(new Set(groups.map((g) => g.id)));
      return;
    }
    setExpanded((prev) => {
      if (prev.size > 0) return prev;
      const target = groups.find((g) => g.files.some((f) => f.path === selected?.path));
      return new Set([target?.id ?? groups[0]!.id]);
    });
  }, [groups, searching, selected?.path]);

  return (
    <>
      <PanelHeader icon={FolderOpen} title={panelLabel(cloud, "files")} />
      <PanelBody className="space-y-4">
        {indexQ.isLoading ? (
          <LoadingPanel label="Loading evidence files…" />
        ) : indexQ.error ? (
          <Card className="p-6">
            <EmptyState
              icon={FolderOpen}
              title="No raw evidence on disk"
              description={(indexQ.error as Error).message}
            />
          </Card>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3">
              <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs">
                <span className="text-fg-subtle">Files </span>
                <span className="mono font-medium text-fg">
                  {fmtNum(indexQ.data?.total_files ?? 0)}
                </span>
              </div>
              <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs">
                <span className="text-fg-subtle">Total size </span>
                <span className="mono font-medium text-fg">
                  {fmtBytes(indexQ.data?.total_bytes ?? 0)}
                </span>
              </div>
              <div className="relative min-w-[220px] flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-subtle" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter files…"
                  className="pl-8"
                />
              </div>
            </div>

            <div className="grid min-h-[560px] grid-cols-1 gap-4 xl:grid-cols-[minmax(280px,380px)_minmax(0,1fr)]">
              <div className="flex min-h-[560px] flex-col gap-2">
                <div className="flex items-center justify-between gap-2 px-0.5">
                  <p className="text-2xs font-medium uppercase tracking-wide text-fg-subtle">
                    {fmtNum(groups.length)} collector{groups.length === 1 ? "" : "s"}
                  </p>
                  <div className="flex gap-2 text-2xs">
                    <button
                      type="button"
                      onClick={expandAll}
                      className="text-fg-subtle hover:text-accent"
                    >
                      Expand all
                    </button>
                    <span className="text-border">|</span>
                    <button
                      type="button"
                      onClick={collapseAll}
                      className="text-fg-subtle hover:text-accent"
                    >
                      Collapse all
                    </button>
                  </div>
                </div>
                <div className="min-h-0 flex-1 space-y-2 overflow-y-auto pr-1">
                  {groups.map((group) => (
                    <CollectorSection
                      key={group.id}
                      group={group}
                      cloud={cloud}
                      expanded={expanded.has(group.id)}
                      onToggle={() => toggleGroup(group.id)}
                      selected={selected}
                      onSelect={setSelected}
                    />
                  ))}
                  {filtered.length === 0 && (
                    <Card className="p-6">
                      <p className="text-center text-xs text-fg-subtle">No matching files.</p>
                    </Card>
                  )}
                </div>
              </div>

              <Card className="flex min-h-[560px] flex-col overflow-hidden p-0">
                {selected ? (
                  <>
                    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3">
                      <div className="min-w-0">
                        <p className="mono text-sm font-medium text-fg break-all">{selected.path}</p>
                        <div className="mt-1 flex flex-wrap gap-2 text-2xs text-fg-subtle">
                          <span className="chip">{selected.kind}</span>
                          {selected.status && <span className="chip">{selected.status}</span>}
                          <span>{fmtBytes(selected.size)}</span>
                          {selected.record_count != null && (
                            <span>{fmtNum(selected.record_count)} records</span>
                          )}
                        </div>
                        {selected.sha256 && (
                          <p className="mt-2 mono text-2xs text-fg-subtle break-all">
                            SHA-256 {selected.sha256}
                          </p>
                        )}
                        {selected.notes && (
                          <p className="mt-2 text-xs text-fg-subtle">{selected.notes}</p>
                        )}
                      </div>
                      <div className="flex shrink-0 gap-2">
                        <a href={api.evidenceDownloadUrl(caseId, selected.path)} download>
                          <Button size="sm" variant="secondary" icon={Download}>
                            Download
                          </Button>
                        </a>
                      </div>
                    </div>
                    <div className="flex-1 overflow-y-auto p-4">
                      <FilePreview caseId={caseId} file={selected} />
                    </div>
                  </>
                ) : (
                  <div className="flex flex-1 items-center justify-center p-8">
                    <EmptyState
                      icon={Braces}
                      title="Select a file"
                      description="Choose a collected source file to preview or download the raw contents."
                    />
                  </div>
                )}
              </Card>
            </div>
          </>
        )}
      </PanelBody>
    </>
  );
}
