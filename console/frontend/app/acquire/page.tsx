"use client";

import { ArtifactInfoButton } from "@/components/artifact-detail-dialog";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Badge, Button, Card, EmptyState, Input, LoadingPanel } from "@/components/ui";
import { api, buildAcquisitionKit } from "@/lib/api";
import { CLOUDS, CLOUD_LABELS, type Cloud } from "@/lib/catalog";
import { CASES_HREF } from "@/lib/routes";
import type { Artifact } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  Anchor,
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronRight,
  Download,
  Layers,
  PackageOpen,
  Plus,
  Search,
  Settings2,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useRef, useState } from "react";

const SEV_COLOR: Record<string, string> = {
  critical: "border-bad-red/40 bg-bad-red/10 text-bad-red",
  extended: "border-warn-amber/40 bg-warn-amber/10 text-warn-amber",
  optional: "border-border bg-surface-2 text-fg-subtle",
};

type ParamSchema = Record<string, { type?: string; required?: boolean; default?: unknown }>;

function paramKeys(schema: ParamSchema | undefined): string[] {
  if (!schema) return [];
  return Object.keys(schema);
}

function parseCloud(raw: string | null): Cloud {
  const c = (raw || "aws").toLowerCase();
  return CLOUDS.includes(c as Cloud) ? (c as Cloud) : "aws";
}

function AcquireContent() {
  const searchParams = useSearchParams();
  const urlCaseId = searchParams.get("case_id")?.trim() || "";
  const urlCloud = parseCloud(searchParams.get("cloud"));
  const urlCollectors = useMemo(
    () =>
      (searchParams.get("collectors") || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    [searchParams],
  );
  const prefillDone = useRef(false);

  const [cloud, setCloud] = useState<Cloud>(urlCloud);
  const [search, setSearch] = useState("");
  const [cart, setCart] = useState<Set<string>>(() => new Set(urlCollectors));
  const [caseId, setCaseId] = useState(urlCaseId);
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [regions, setRegions] = useState("");
  const [project, setProject] = useState("");
  const [subscription, setSubscription] = useState("");
  const [maxRecords, setMaxRecords] = useState("");
  const [artifactParams, setArtifactParams] = useState<Record<string, Record<string, string>>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [includeIam, setIncludeIam] = useState(true);
  const [building, setBuilding] = useState(false);
  const [error, setError] = useState("");

  const artifacts = useQuery({
    queryKey: ["artifacts", cloud],
    queryFn: () => api.artifacts(cloud),
  });
  const packs = useQuery({ queryKey: ["packs", cloud], queryFn: () => api.packs(cloud) });

  const all = artifacts.data?.artifacts ?? [];

  useEffect(() => {
    if (prefillDone.current || !all.length) return;
    prefillDone.current = true;
    if (urlCaseId) setCaseId(urlCaseId);
    if (urlCloud) setCloud(urlCloud);
    if (urlCollectors.length) {
      const valid = new Set(all.map((a) => a.collector));
      setCart(new Set(urlCollectors.filter((c) => valid.has(c))));
    }
  }, [all, urlCaseId, urlCloud, urlCollectors]);

  const fromCase = !!urlCaseId;
  const preselectedCount = urlCollectors.length;
  const visible = useMemo(() => {
    const s = search.trim().toLowerCase();
    if (!s) return all;
    return all.filter(
      (a) =>
        a.name.toLowerCase().includes(s) ||
        a.collector.toLowerCase().includes(s) ||
        a.description.toLowerCase().includes(s) ||
        a.category.toLowerCase().includes(s),
    );
  }, [all, search]);

  const byCategory = useMemo(() => {
    const groups = new Map<string, typeof visible>();
    for (const a of visible) {
      const key = a.category || "Other";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(a);
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [visible]);

  const cartForCloud = useMemo(
    () => all.filter((a) => cart.has(a.collector)),
    [all, cart],
  );

  const toggle = (collector: string) =>
    setCart((prev) => {
      const next = new Set(prev);
      next.has(collector) ? next.delete(collector) : next.add(collector);
      return next;
    });

  const toggleExpand = (collector: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(collector) ? next.delete(collector) : next.add(collector);
      return next;
    });
  };

  const setParam = (collector: string, key: string, value: string) =>
    setArtifactParams((prev) => ({
      ...prev,
      [collector]: { ...(prev[collector] || {}), [key]: value },
    }));

  const addPack = (artifactKeys: string[]) =>
    setCart((prev) => new Set([...prev, ...artifactKeys]));

  const clear = () => setCart(new Set());

  const download = async () => {
    setBuilding(true);
    setError("");
    try {
      const regionList = regions
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean);
      const capRaw = maxRecords.trim();
      const cap = capRaw === "" ? undefined : Number(capRaw);
      const params: Record<string, Record<string, unknown>> = {};
      for (const a of cartForCloud) {
        const p = artifactParams[a.collector];
        if (p && Object.values(p).some((v) => v.trim())) {
          params[a.collector] = Object.fromEntries(
            Object.entries(p).filter(([, v]) => v.trim()).map(([k, v]) => [k, v.trim()]),
          );
        }
      }
      await buildAcquisitionKit({
        cloud,
        case_id: caseId.trim() || "CASE-PENDING",
        artifacts: cartForCloud.map((a) => a.collector),
        include_iam: includeIam,
        since: since.trim() || undefined,
        until: until.trim() || undefined,
        regions: regionList.length ? regionList : undefined,
        project: cloud === "gcp" ? project.trim() || undefined : undefined,
        subscription: cloud === "azure" ? subscription.trim() || undefined : undefined,
        max_records_per_source: cap === undefined || Number.isNaN(cap) ? undefined : cap,
        artifact_parameters: Object.keys(params).length ? params : undefined,
      });
    } catch (e: any) {
      setError(e.message || "Kit build failed");
    } finally {
      setBuilding(false);
    }
  };

  const tabs = CLOUDS.map((c) => ({ id: c, label: CLOUD_LABELS[c] }));

  const renderParams = (a: Artifact) => {
    const keys = paramKeys(a.parameters as ParamSchema | undefined);
    if (!keys.length) return null;
    const open = expanded.has(a.collector);
    return (
      <div className="mt-2 border-t border-border/60 pt-2" onClick={(e) => e.stopPropagation()}>
        <button
          type="button"
          onClick={(e) => toggleExpand(a.collector, e)}
          className="flex items-center gap-1 text-2xs text-fg-subtle hover:text-fg"
        >
          {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          <Settings2 className="h-3 w-3" /> Parameters
        </button>
        {open && (
          <div className="mt-2 space-y-2">
            {keys.map((key) => (
              <label key={key} className="block space-y-1">
                <span className="mono text-2xs text-fg-subtle">{key}</span>
                <Input
                  className="h-8 text-xs"
                  placeholder={String((a.parameters as ParamSchema)?.[key]?.type || key)}
                  value={artifactParams[a.collector]?.[key] || ""}
                  onChange={(e) => setParam(a.collector, key, e.target.value)}
                />
              </label>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Anchor className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">Acquire</h1>
              <p className="text-xs text-fg-subtle">
                Build a read-only collection kit for the client to run
              </p>
            </div>
          </div>
          <Link href={fromCase ? `/cases/${encodeURIComponent(caseId)}/collection` : CASES_HREF}>
            <Button variant="ghost" icon={ArrowLeft}>
              {fromCase ? "Back to case" : "Cases"}
            </Button>
          </Link>
        </div>
      </header>

      <main className="mx-auto grid max-w-6xl grid-cols-1 gap-6 px-6 py-8 lg:grid-cols-[1fr_20rem]">
        {fromCase && preselectedCount > 0 && (
          <div className="lg:col-span-2 rounded-lg border border-accent/30 bg-accent/5 px-4 py-3 text-xs text-fg">
            Pre-selected <span className="mono font-medium">{preselectedCount}</span> missing log
            source{preselectedCount === 1 ? "" : "s"} for case{" "}
            <span className="mono font-medium">{urlCaseId}</span>. Adjust the kit, then download for
            the client to run.
          </div>
        )}
        <div className="min-w-0">
          <div className="mb-4 flex items-center gap-1 border-b border-border">
            {tabs.map((t) => {
              const active = cloud === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setCloud(t.id)}
                  className={cn(
                    "relative -mb-px flex items-center gap-2 px-4 py-2.5 text-sm transition-colors",
                    active ? "text-fg" : "text-fg-subtle hover:text-fg",
                  )}
                >
                  <CloudProviderIcon cloud={t.id} size={20} />
                  {t.label}
                  {active && (
                    <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-accent" />
                  )}
                </button>
              );
            })}
          </div>

          <div className="mb-4 flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" />
              <Input
                className="pl-9"
                placeholder="Search artifacts by name, collector, or category…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>

          {(packs.data?.packs.length ?? 0) > 0 && (
            <div className="mb-5">
              <div className="mb-2 flex items-center gap-2 text-xs font-medium text-fg-subtle">
                <Layers className="h-3.5 w-3.5" /> Curated packs
              </div>
              <div className="flex flex-wrap gap-2">
                {packs.data!.packs.map((p) => (
                  <button
                    key={p.pack}
                    onClick={() => addPack(p.artifacts)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-fg transition-colors hover:border-accent/50 hover:bg-surface-2"
                    title={`${p.description} — adds ${p.artifacts.length} artifacts`}
                  >
                    <Plus className="h-3.5 w-3.5 text-accent" />
                    {p.pack}
                    <span className="mono text-2xs text-fg-subtle">{p.artifacts.length}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {artifacts.isLoading ? (
            <LoadingPanel label="Loading artifact library…" />
          ) : artifacts.error ? (
            <Card className="p-6">
              <EmptyState
                icon={PackageOpen}
                title="Can't reach the backend"
                description="Start the console API, then reload."
              />
            </Card>
          ) : visible.length === 0 ? (
            <Card className="py-4">
              <EmptyState icon={Search} title="No matching artifacts" description="Try a different search." />
            </Card>
          ) : (
            <div className="space-y-6">
              {byCategory.map(([category, items]) => (
                <div key={category}>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                    {category}
                  </h3>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    {items.map((a) => {
                      const selected = cart.has(a.collector);
                      return (
                        <div
                          key={a.collector}
                          role="button"
                          tabIndex={0}
                          onClick={() => toggle(a.collector)}
                          onKeyDown={(e) => e.key === "Enter" && toggle(a.collector)}
                          className={cn(
                            "group flex cursor-pointer flex-col rounded-lg border p-3 text-left transition-colors",
                            selected
                              ? "border-accent/50 bg-accent/5"
                              : "border-border bg-surface hover:border-accent/30",
                          )}
                        >
                          <div className="flex items-start gap-3">
                            <span
                              className={cn(
                                "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border",
                                selected
                                  ? "border-accent bg-accent text-accent-fg"
                                  : "border-border bg-surface-2",
                              )}
                            >
                              {selected && <Check className="h-3 w-3" />}
                            </span>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <span className="mono truncate text-sm font-medium text-fg">
                                  {a.collector}
                                </span>
                                <ArtifactInfoButton collector={a.collector} cloud={cloud} />
                                {a.severity && (
                                  <Badge className={SEV_COLOR[a.severity] ?? SEV_COLOR.optional}>
                                    {a.severity}
                                  </Badge>
                                )}
                              </div>
                              <p className="mt-0.5 line-clamp-2 text-xs text-fg-subtle">
                                {a.description || a.name}
                              </p>
                              {selected && renderParams(a)}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <aside className="lg:sticky lg:top-8 lg:self-start">
          <Card>
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <h3 className="flex items-center gap-2 text-sm font-semibold">
                <Download className="h-4 w-4 text-accent" /> Collection kit
              </h3>
              {cartForCloud.length > 0 && (
                <button
                  onClick={clear}
                  className="inline-flex items-center gap-1 text-2xs text-fg-subtle hover:text-bad-red"
                >
                  <Trash2 className="h-3 w-3" /> Clear
                </button>
              )}
            </div>

            <div className="p-4">
              {cartForCloud.length === 0 ? (
                <p className="py-6 text-center text-sm text-fg-subtle">
                  Pick artifacts (or a pack) to add them to the kit.
                </p>
              ) : (
                <ul className="mb-4 max-h-40 space-y-1 overflow-auto">
                  {cartForCloud.map((a) => (
                    <li
                      key={a.collector}
                      className="flex items-center justify-between gap-2 rounded px-1.5 py-1 text-xs"
                    >
                      <span className="mono truncate text-fg">{a.collector}</span>
                      <button
                        onClick={() => toggle(a.collector)}
                        className="text-fg-subtle hover:text-bad-red"
                        aria-label={`Remove ${a.collector}`}
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}

              <div className="space-y-3 border-t border-border pt-3">
                <p className="text-2xs font-medium uppercase tracking-wide text-fg-subtle">
                  Global collection window
                </p>
                <label className="block space-y-1.5">
                  <span className="text-xs font-medium text-fg">Case ID</span>
                  <Input
                    value={caseId}
                    onChange={(e) => setCaseId(e.target.value)}
                    placeholder="CASE-2026-0042"
                  />
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <label className="block space-y-1">
                    <span className="text-2xs text-fg-subtle">Since</span>
                    <Input
                      value={since}
                      onChange={(e) => setSince(e.target.value)}
                      placeholder="2026-05-01"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-2xs text-fg-subtle">Until</span>
                    <Input
                      value={until}
                      onChange={(e) => setUntil(e.target.value)}
                      placeholder="2026-06-01"
                    />
                  </label>
                </div>
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-subtle">Regions (comma-separated)</span>
                  <Input
                    value={regions}
                    onChange={(e) => setRegions(e.target.value)}
                    placeholder={cloud === "aws" ? "us-east-1,us-west-2" : "optional"}
                  />
                </label>
                {cloud === "gcp" && (
                  <label className="block space-y-1">
                    <span className="text-2xs text-fg-subtle">Project ID(s)</span>
                    <Input
                      value={project}
                      onChange={(e) => setProject(e.target.value)}
                      placeholder="my-project"
                    />
                  </label>
                )}
                {cloud === "azure" && (
                  <label className="block space-y-1">
                    <span className="text-2xs text-fg-subtle">Subscription ID(s)</span>
                    <Input
                      value={subscription}
                      onChange={(e) => setSubscription(e.target.value)}
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    />
                  </label>
                )}
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-subtle">Max records per source (0 = no cap)</span>
                  <Input
                    value={maxRecords}
                    onChange={(e) => setMaxRecords(e.target.value)}
                    placeholder="200000"
                    inputMode="numeric"
                  />
                </label>
              </div>

              <label className="mt-3 flex cursor-pointer items-center gap-2 text-xs text-fg-subtle">
                <input
                  type="checkbox"
                  checked={includeIam}
                  onChange={(e) => setIncludeIam(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-border"
                />
                <ShieldCheck className="h-3.5 w-3.5" />
                Bundle read-only IAM policy
              </label>

              {error && <p className="mt-3 text-xs text-bad-red">{error}</p>}

              <Button
                variant="primary-dark"
                icon={Download}
                className="mt-4 w-full justify-center"
                disabled={cartForCloud.length === 0 || building}
                loading={building}
                onClick={download}
              >
                {building ? "Building…" : `Download kit (${cartForCloud.length})`}
              </Button>
              <p className="mt-2 text-center text-2xs text-fg-subtle">
                {CLOUD_LABELS[cloud]} · acquisition.yaml + run.sh
              </p>
            </div>
          </Card>
        </aside>
      </main>
    </div>
  );
}

export default function AcquirePage() {
  return (
    <Suspense fallback={<LoadingPanel label="Loading acquire…" />}>
      <AcquireContent />
    </Suspense>
  );
}
