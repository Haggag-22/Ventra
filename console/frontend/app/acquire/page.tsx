"use client";

import { AcquireHandoffDialog } from "@/components/acquire-handoff-dialog";
import { AcquireParamFields, MultiValueInput, serializeParamValues, type ParamValues } from "@/components/acquire-param-fields";
import { ArtifactInfoButton } from "@/components/artifact-detail-dialog";
import { IamActionsDialog } from "@/components/iam-actions-dialog";
import { ArtifactIcon } from "@/components/artifact-icon";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Button, Card, EmptyState, Input, LoadingPanel } from "@/components/ui";
import { saveKitHandoff, type KitHandoffRecord } from "@/lib/acquire-handoff";
import {
  buildTransportSpec,
  HANDOFF_MODES,
  type HandoffMode,
} from "@/lib/handoff-modes";
import {
  missingRequiredParams,
  resolvedParamFields,
  validateArtifactParams,
} from "@/lib/artifact-params";
import { api, buildAcquisitionKit, previewAcquisitionKit, type AcquisitionBuild } from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { CLOUDS, CLOUD_LABELS, compareCollectorCategories, type Cloud } from "@/lib/catalog";
import {
  DEPLOYMENT_PROFILES,
  isEnterpriseProfile,
  parseDeploymentProfile,
  type DeploymentProfile,
} from "@/lib/deployment-profiles";
import { downloadTextFile } from "@/lib/download";
import { displayCategoryLabel } from "@/lib/format";
import { CASES_HREF } from "@/lib/routes";
import type { Artifact } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import {
  AlertCircle,
  Anchor,
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronRight,
  Download,
  FileJson,
  Layers,
  PackageOpen,
  Plus,
  Search,
  Settings2,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";

const PACK_LABELS: Record<string, string> = {
  "baseline-ir-aws": "Baseline AWS",
  "baseline-ir-azure": "Baseline Azure",
  "baseline-ir-gcp": "Baseline GCP",
};

function displayPack(pack: string): string {
  return (
    PACK_LABELS[pack] ??
    pack
      .split("-")
      .filter((w) => w !== "ir")
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(" ")
  );
}

function parseCloud(raw: string | null): Cloud {
  const c = (raw || "aws").toLowerCase();
  return CLOUDS.includes(c as Cloud) ? (c as Cloud) : "aws";
}

function joinScopeValues(values: string[]): string | undefined {
  const cleaned = values.map((v) => v.trim()).filter(Boolean);
  return cleaned.length ? cleaned.join(",") : undefined;
}

function buildRequestBody(
  cloud: Cloud,
  caseId: string,
  collectors: string[],
  since: string,
  until: string,
  regions: string,
  projectIds: string[],
  subscriptionIds: string[],
  azureTenantId: string,
  azureClientId: string,
  awsProfile: string,
  artifactParams: Record<string, ParamValues>,
  cartForCloud: Artifact[],
  deploymentProfile: DeploymentProfile,
  maxRecordsPerSource: string,
  transport?: string,
): AcquisitionBuild {
  const regionList = regions
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
  const params: Record<string, Record<string, unknown>> = {};
  for (const a of cartForCloud) {
    const p = artifactParams[a.collector];
    if (!p) continue;
    const serialized = serializeParamValues(p);
    if (Object.keys(serialized).length) {
      params[a.collector] = serialized;
    }
  }
  return {
    cloud,
    case_id: caseId.trim() || "CASE-PENDING",
    artifacts: collectors,
    include_iam: true,
    since: since.trim() || undefined,
    until: until.trim() || undefined,
    regions: regionList.length ? regionList : undefined,
    project: cloud === "gcp" ? joinScopeValues(projectIds) : undefined,
    subscription: cloud === "azure" ? joinScopeValues(subscriptionIds) : undefined,
    azure_tenant_id: cloud === "azure" ? azureTenantId.trim() || undefined : undefined,
    azure_client_id: cloud === "azure" ? azureClientId.trim() || undefined : undefined,
    aws_profile: cloud === "aws" ? awsProfile.trim() || undefined : undefined,
    artifact_parameters: Object.keys(params).length ? params : undefined,
    deployment_profile: deploymentProfile,
    max_records_per_source: (() => {
      const trimmed = maxRecordsPerSource.trim();
      if (!trimmed) return undefined;
      const n = Number(trimmed);
      if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) return undefined;
      return n;
    })(),
    transport: transport?.trim() || undefined,
    bundle_wheel: true,
    require_wheel: true,
  };
}

function AcquireContent() {
  const router = useRouter();
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
  const [projectIds, setProjectIds] = useState<string[]>([]);
  const [subscriptionIds, setSubscriptionIds] = useState<string[]>([]);
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureClientId, setAzureClientId] = useState("");
  const [awsProfile, setAwsProfile] = useState("");
  const [maxRecordsPerSource, setMaxRecordsPerSource] = useState("");
  const [artifactParams, setArtifactParams] = useState<Record<string, ParamValues>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [deploymentProfile, setDeploymentProfile] = useState<DeploymentProfile>("cloudshell");
  const [handoffMode, setHandoffMode] = useState<HandoffMode>("file");
  const [s3Bucket, setS3Bucket] = useState("");
  const [s3Prefix, setS3Prefix] = useState("cases");
  const [presignedUrl, setPresignedUrl] = useState("");
  const [building, setBuilding] = useState(false);
  const [error, setError] = useState("");
  const [iamPreview, setIamPreview] = useState<Awaited<ReturnType<typeof previewAcquisitionKit>> | null>(
    null,
  );
  const [iamPreviewError, setIamPreviewError] = useState("");
  const [iamActionsOpen, setIamActionsOpen] = useState(false);
  const [handoff, setHandoff] = useState<KitHandoffRecord | null>(null);
  const [handoffOpen, setHandoffOpen] = useState(false);

  const artifacts = useQuery({
    queryKey: ["artifacts", cloud],
    queryFn: () => api.artifacts(cloud),
    staleTime: 0,
  });
  const packs = useQuery({ queryKey: ["packs", cloud], queryFn: () => api.packs(cloud) });

  const all = (artifacts.data?.artifacts ?? []).filter((a) => a.selectable !== false);

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
    return [...groups.entries()].sort((a, b) => compareCollectorCategories(a[0], b[0]));
  }, [visible]);

  const cartForCloud = useMemo(
    () => all.filter((a) => cart.has(a.collector)),
    [all, cart],
  );

  const collectors = useMemo(() => cartForCloud.map((a) => a.collector), [cartForCloud]);

  const transportSpec = useMemo(() => {
    if (!isEnterpriseProfile(deploymentProfile)) return "";
    return buildTransportSpec(handoffMode, s3Bucket, s3Prefix, presignedUrl);
  }, [deploymentProfile, handoffMode, s3Bucket, s3Prefix, presignedUrl]);

  const requestBody = useMemo(
    () =>
      buildRequestBody(
        cloud,
        caseId,
        collectors,
        since,
        until,
        regions,
        projectIds,
        subscriptionIds,
        azureTenantId,
        azureClientId,
        awsProfile,
        artifactParams,
        cartForCloud,
        deploymentProfile,
        maxRecordsPerSource,
        isEnterpriseProfile(deploymentProfile) ? transportSpec : undefined,
      ),
    [
      cloud,
      caseId,
      collectors,
      since,
      until,
      regions,
      projectIds,
      subscriptionIds,
      azureTenantId,
      azureClientId,
      awsProfile,
      maxRecordsPerSource,
      artifactParams,
      cartForCloud,
      deploymentProfile,
      transportSpec,
    ],
  );

  useEffect(() => {
    if (!collectors.length) {
      setIamPreview(null);
      setIamPreviewError("");
      return;
    }
    const timer = window.setTimeout(() => {
      previewAcquisitionKit(requestBody)
        .then((p) => {
          setIamPreview(p);
          setIamPreviewError("");
        })
        .catch((e: Error) => {
          setIamPreview(null);
          setIamPreviewError(e.message || "Preview failed");
        });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [requestBody, collectors.length]);

  const toggle = (collector: string) => {
    const wasSelected = cart.has(collector);
    setCart((prev) => {
      const next = new Set(prev);
      next.has(collector) ? next.delete(collector) : next.add(collector);
      return next;
    });
    if (wasSelected) {
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(collector);
        return next;
      });
    }
  };

  const toggleParamExpand = (collector: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(collector) ? next.delete(collector) : next.add(collector);
      return next;
    });

  const setCollectorParams = (collector: string, values: ParamValues) =>
    setArtifactParams((prev) => ({
      ...prev,
      [collector]: values,
    }));

  const addPack = (artifactKeys: string[]) =>
    setCart((prev) => new Set([...prev, ...artifactKeys]));

  const clear = () => setCart(new Set());

  const downloadIamPreview = () => {
    if (!iamPreview?.iam_policies) return;
    for (const [name, policy] of Object.entries(iamPreview.iam_policies)) {
      downloadTextFile(`preview-${name}`, JSON.stringify(policy, null, 2) + "\n", "application/json");
    }
  };

  const download = async () => {
    const capRaw = maxRecordsPerSource.trim();
    if (capRaw) {
      const cap = Number(capRaw);
      if (!Number.isFinite(cap) || cap < 0 || !Number.isInteger(cap)) {
        setError("Records count to collect must be a whole number.");
        return;
      }
    }
    const validation = validateArtifactParams(cartForCloud, artifactParams);
    if (!validation.ok) {
      setError(validation.errors.map((e) => `${e.label}: ${e.message}`).join("; "));
      setExpanded((prev) => new Set([...prev, ...validation.errors.map((e) => e.collector)]));
      return;
    }
    if (isEnterpriseProfile(deploymentProfile)) {
      if (handoffMode === "s3_ir_bucket" && !s3Bucket.trim()) {
        setError("IR bucket handoff needs your evidence bucket name.");
        return;
      }
      if (handoffMode === "presigned" && !presignedUrl.trim()) {
        setError("Presigned handoff needs a PUT URL for the client kit.");
        return;
      }
    }
    setBuilding(true);
    setError("");
    try {
      await buildAcquisitionKit(requestBody);
      const record: KitHandoffRecord = {
        caseId: requestBody.case_id || "CASE-PENDING",
        cloud,
        collectors,
        deploymentProfile,
        builtAt: new Date().toISOString(),
        ventraVersion: iamPreview?.ventra_version,
        includeIam: true,
        handoffMode: isEnterpriseProfile(deploymentProfile) ? handoffMode : "file",
        transport: transportSpec || undefined,
      };
      saveKitHandoff(record);
      setHandoff(record);
      setHandoffOpen(true);
    } catch (e: any) {
      setError(e.message || "Kit build failed");
    } finally {
      setBuilding(false);
    }
  };

  const openImport = useCallback(() => {
    setHandoffOpen(false);
    router.push(`${CASES_HREF}?import_case=${encodeURIComponent(handoff?.caseId || caseId.trim() || "CASE-PENDING")}`);
  }, [router, handoff?.caseId, caseId]);

  const openImportS3 = useCallback(() => {
    setHandoffOpen(false);
    router.push(`${CASES_HREF}?import_s3=1`);
  }, [router]);

  const tabs = CLOUDS.map((c) => ({ id: c, label: CLOUD_LABELS[c] }));

  const renderParamHints = (a: Artifact) => {
    const missing = missingRequiredParams(a, artifactParams[a.collector]);
    if (!missing.length) return null;
    return (
      <div className="mt-1.5 flex flex-wrap gap-1">
        {missing.map((key) => (
          <span
            key={key}
            className="inline-flex items-center gap-1 rounded bg-warn-amber/15 px-1.5 py-0.5 text-2xs text-warn-amber"
          >
            <AlertCircle className="h-3 w-3" />
            {key.replace(/_/g, " ")} required
          </span>
        ))}
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

      <main className="mx-auto max-w-6xl space-y-6 px-6 py-8">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_24rem]">
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
                    className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs font-medium text-fg transition-colors hover:border-accent/50 hover:bg-surface-2"
                    title={`Add ${p.artifacts.length} artifacts`}
                  >
                    <Plus className="h-3.5 w-3.5 text-accent" />
                    {displayPack(p.pack)}
                    <span className="mono text-2xs text-fg-subtle">{p.artifacts.length}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {artifacts.isPending ? (
            <LoadingPanel label="Loading artifact library…" />
          ) : artifacts.isError ? (
            <Card className="p-6">
              <EmptyState
                icon={PackageOpen}
                title="Can't load artifacts"
                description={
                  artifacts.error instanceof Error
                    ? artifacts.error.message
                    : "Start the console API, then reload."
                }
              />
              <Button
                variant="ghost"
                size="sm"
                className="mx-auto mt-3 flex"
                onClick={() => artifacts.refetch()}
              >
                Retry
              </Button>
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
                    {displayCategoryLabel(category)}
                  </h3>
                  <div className="overflow-hidden rounded-lg border border-border divide-y divide-border">
                    {items.map((a) => {
                      const selected = cart.has(a.collector);
                      const fields = resolvedParamFields(a);
                      const hasParams = fields.length > 0;
                      const paramsExpanded = expanded.has(a.collector);
                      const missing = selected ? missingRequiredParams(a, artifactParams[a.collector]) : [];
                      return (
                        <div
                          key={a.collector}
                          className={cn(
                            "transition-colors",
                            selected ? "bg-accent/5" : "bg-surface hover:bg-surface-2/50",
                          )}
                        >
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => toggle(a.collector)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                toggle(a.collector);
                              }
                            }}
                            className={cn(
                              "flex cursor-pointer items-center gap-3 px-3 py-2.5 text-left",
                              selected ? "border-l-2 border-l-accent pl-[10px]" : "border-l-2 border-l-transparent",
                            )}
                          >
                            <span
                              className={cn(
                                "flex h-4 w-4 shrink-0 items-center justify-center rounded border",
                                selected
                                  ? "border-accent bg-accent text-accent-fg"
                                  : "border-border bg-surface-2",
                              )}
                            >
                              {selected && <Check className="h-3 w-3" />}
                            </span>
                            <ArtifactIcon cloud={cloud} collector={a.collector} size={24} />
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="truncate text-sm font-medium text-fg">
                                  {displayArtifactLabel(a.collector)}
                                </span>
                                {selected && hasParams && !paramsExpanded && (
                                  <span className="inline-flex shrink-0 items-center gap-1 text-2xs text-fg-subtle">
                                    <Settings2 className="h-3 w-3" />
                                    {fields.length}
                                  </span>
                                )}
                                {missing.length > 0 && (
                                  <span className="inline-flex shrink-0 items-center gap-0.5 text-2xs text-warn-amber">
                                    <AlertCircle className="h-3 w-3" />
                                    {missing.length}
                                  </span>
                                )}
                              </div>
                              {paramsExpanded && a.description ? (
                                <p className="mt-0.5 line-clamp-1 text-2xs text-fg-subtle">
                                  {a.description}
                                </p>
                              ) : null}
                            </div>
                            <ArtifactInfoButton collector={a.collector} cloud={cloud} />
                            {selected && hasParams && (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleParamExpand(a.collector);
                                }}
                                className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-fg-subtle hover:bg-surface-2 hover:text-fg"
                                aria-label={paramsExpanded ? "Collapse parameters" : "Expand parameters"}
                                aria-expanded={paramsExpanded}
                              >
                                {paramsExpanded ? (
                                  <ChevronDown className="h-4 w-4" />
                                ) : (
                                  <ChevronRight className="h-4 w-4" />
                                )}
                              </button>
                            )}
                          </div>
                          {selected && hasParams && paramsExpanded && (
                            <div className="border-t border-border/60 bg-surface-2/30 px-3 py-3 pl-11">
                              {renderParamHints(a)}
                              <AcquireParamFields
                                compact
                                className="mt-2"
                                fields={fields}
                                values={artifactParams[a.collector] || {}}
                                onChange={(values) => setCollectorParams(a.collector, values)}
                              />
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <aside className="space-y-4 lg:sticky lg:top-8 lg:self-start">
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
                      className="flex items-center gap-2 rounded px-1.5 py-1 text-xs"
                    >
                      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                        <span className="flex min-w-0 items-center gap-2">
                          <ArtifactIcon cloud={cloud} collector={a.collector} size={18} />
                          <span className="truncate text-fg">{displayArtifactLabel(a.collector)}</span>
                        </span>
                        {renderParamHints(a)}
                      </span>
                      <button
                        onClick={() => toggle(a.collector)}
                        className="shrink-0 text-fg-subtle hover:text-bad-red"
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
                  Deployment profile
                </p>
                <div className="space-y-2">
                  {DEPLOYMENT_PROFILES.map((p) => (
                    <label
                      key={p.id}
                      className={cn(
                        "flex cursor-pointer gap-2 rounded-md border px-2.5 py-2 text-xs transition-colors",
                        deploymentProfile === p.id
                          ? "border-accent/50 bg-accent/5"
                          : "border-border hover:border-accent/30",
                      )}
                    >
                      <input
                        type="radio"
                        name="deployment_profile"
                        checked={deploymentProfile === p.id}
                        onChange={() => setDeploymentProfile(parseDeploymentProfile(p.id))}
                        className="mt-0.5"
                      />
                      <span>
                        <span className="font-medium text-fg">{p.label}</span>
                        <span className="mt-0.5 block text-2xs text-fg-subtle">{p.summary}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              {isEnterpriseProfile(deploymentProfile) && (
                <div className="space-y-3 border-t border-border pt-3">
                  <p className="text-2xs font-medium uppercase tracking-wide text-fg-subtle">
                    Evidence handoff
                  </p>
                  <div className="space-y-2">
                    {HANDOFF_MODES.map((mode) => (
                      <label
                        key={mode.id}
                        className={cn(
                          "flex cursor-pointer gap-2 rounded-md border px-2.5 py-2 text-xs transition-colors",
                          handoffMode === mode.id
                            ? "border-accent/50 bg-accent/5"
                            : "border-border hover:border-accent/30",
                        )}
                      >
                        <input
                          type="radio"
                          name="handoff_mode"
                          checked={handoffMode === mode.id}
                          onChange={() => setHandoffMode(mode.id)}
                          className="mt-0.5"
                        />
                        <span>
                          <span className="font-medium text-fg">{mode.label}</span>
                          <span className="mt-0.5 block text-2xs text-fg-subtle">{mode.summary}</span>
                        </span>
                      </label>
                    ))}
                  </div>

                  {handoffMode === "s3_ir_bucket" && (
                    <>
                      <p className="text-2xs text-fg-subtle">
                        Your Ventra server must be able to read this bucket (Import from S3 uses
                        server-side AWS credentials, not the client browser).
                      </p>
                      <label className="block space-y-1">
                        <span className="text-2xs text-fg-subtle">Your IR bucket</span>
                        <Input
                          value={s3Bucket}
                          onChange={(e) => setS3Bucket(e.target.value)}
                          placeholder="ir-evidence-bucket"
                          className="mono text-xs"
                        />
                      </label>
                      <label className="block space-y-1">
                        <span className="text-2xs text-fg-subtle">Prefix</span>
                        <Input
                          value={s3Prefix}
                          onChange={(e) => setS3Prefix(e.target.value)}
                          placeholder="cases"
                          className="mono text-xs"
                        />
                      </label>
                    </>
                  )}

                  {handoffMode === "presigned" && (
                    <>
                      <p className="text-2xs text-fg-subtle">
                        Generate a presigned PUT URL in your IR bucket, paste it here, and send
                        the kit to the client. After upload, ingest from your bucket.
                      </p>
                      <label className="block space-y-1">
                        <span className="text-2xs text-fg-subtle">Presigned PUT URL</span>
                        <Input
                          value={presignedUrl}
                          onChange={(e) => setPresignedUrl(e.target.value)}
                          placeholder="https://bucket.s3.amazonaws.com/key?X-Amz-..."
                          className="mono text-xs"
                        />
                      </label>
                    </>
                  )}

                  {handoffMode === "file" && (
                    <p className="text-2xs text-fg-subtle">
                      No automatic upload — client returns the sealed package and you use Import
                      package on Cases.
                    </p>
                  )}

                  {transportSpec && (
                    <p className="mono text-2xs text-accent">{transportSpec}</p>
                  )}
                </div>
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
                  <span className="text-2xs text-fg-subtle">Regions</span>
                  <Input
                    value={regions}
                    onChange={(e) => setRegions(e.target.value)}
                    placeholder={cloud === "aws" ? "us-east-1,us-west-2" : "optional"}
                  />
                </label>
                {cloud === "gcp" && (
                  <div className="block space-y-1">
                    <span className="text-2xs text-fg-subtle">Project ID(s)</span>
                    <MultiValueInput
                      items={projectIds}
                      placeholder="my-project"
                      onChange={setProjectIds}
                    />
                  </div>
                )}
                {cloud === "aws" && (
                  <label className="block space-y-1">
                    <span className="text-2xs text-fg-subtle">AWS profile (optional)</span>
                    <Input
                      value={awsProfile}
                      onChange={(e) => setAwsProfile(e.target.value)}
                      placeholder="Named profile from ~/.aws/credentials"
                      className="mono text-xs"
                    />
                  </label>
                )}
                {cloud === "azure" && (
                  <>
                    <div className="block space-y-1">
                      <span className="text-2xs text-fg-subtle">Subscription ID(s)</span>
                      <MultiValueInput
                        items={subscriptionIds}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        onChange={setSubscriptionIds}
                      />
                    </div>
                    <label className="block space-y-1">
                      <span className="text-2xs text-fg-subtle">Entra tenant ID (optional)</span>
                      <Input
                        value={azureTenantId}
                        onChange={(e) => setAzureTenantId(e.target.value)}
                        placeholder="Embedded in acquisition.yaml — or use AZURE_TENANT_ID"
                        className="mono text-xs"
                      />
                    </label>
                    <label className="block space-y-1">
                      <span className="text-2xs text-fg-subtle">App client ID (optional)</span>
                      <Input
                        value={azureClientId}
                        onChange={(e) => setAzureClientId(e.target.value)}
                        placeholder="Embedded in acquisition.yaml — or use AZURE_CLIENT_ID"
                        className="mono text-xs"
                      />
                    </label>
                    <p className="text-2xs text-fg-subtle">
                      Set <span className="mono">AZURE_CLIENT_SECRET</span> in the environment before
                      running <span className="mono">ventra.py</span> — never put secrets in the kit zip.
                    </p>
                  </>
                )}
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-subtle">Records count to collect (optional)</span>
                  <Input
                    type="number"
                    min={0}
                    step={1}
                    value={maxRecordsPerSource}
                    onChange={(e) => setMaxRecordsPerSource(e.target.value)}
                    placeholder="Unlimited"
                    className="mono text-xs"
                  />
                </label>
              </div>

              <div className="mt-3 space-y-2 border-t border-border pt-3">
                <div className="flex items-center gap-2 text-xs font-medium text-fg">
                  <ShieldCheck className="h-3.5 w-3.5 text-fg-subtle" />
                  Read-only IAM policy
                </div>
                {collectors.length > 0 && (
                  <div className="rounded-md border border-border bg-surface-2 px-2.5 py-2.5">
                    {iamPreviewError ? (
                      <p className="text-xs text-bad-red">{iamPreviewError}</p>
                    ) : iamPreview ? (
                      <>
                        <p className="text-xs text-fg">
                          <span className="mono font-medium">{iamPreview.iam_action_count}</span> IAM
                          action{iamPreview.iam_action_count === 1 ? "" : "s"}
                          {iamPreview.implicit_collectors.length > 0 && (
                            <span className="text-fg-subtle">
                              {" "}
                              (+ {iamPreview.implicit_collectors.length} implicit)
                            </span>
                          )}
                        </p>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            onClick={() => setIamActionsOpen(true)}
                            disabled={iamPreview.iam_actions.length === 0}
                          >
                            Show IAM actions
                          </Button>
                          {Object.keys(iamPreview.iam_policies).length > 0 && (
                            <Button
                              type="button"
                              variant="secondary"
                              size="sm"
                              icon={FileJson}
                              onClick={downloadIamPreview}
                            >
                              Download
                            </Button>
                          )}
                        </div>
                      </>
                    ) : (
                      <p className="text-xs text-fg-subtle">Calculating IAM preview…</p>
                    )}
                  </div>
                )}
              </div>

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
            </div>
          </Card>
        </aside>
        </div>
      </main>

      <IamActionsDialog
        open={iamActionsOpen}
        onClose={() => setIamActionsOpen(false)}
        cloud={cloud}
        actions={iamPreview?.iam_actions ?? []}
        actionCount={iamPreview?.iam_action_count ?? 0}
        implicitCount={iamPreview?.implicit_collectors.length ?? 0}
      />

      <AcquireHandoffDialog
        open={handoffOpen}
        handoff={handoff}
        onClose={() => setHandoffOpen(false)}
        onImport={openImport}
        onImportS3={openImportS3}
      />
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
