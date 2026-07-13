"use client";

import { AcquireParamFields, MultiValueInput, type ParamValues } from "@/components/acquire-param-fields";
import { ArtifactInfoButton } from "@/components/artifact-detail-dialog";
import { IamActionsDialog } from "@/components/iam-actions-dialog";
import { ArtifactIcon } from "@/components/artifact-icon";
import { CloudProviderIcon } from "@/components/cloud-provider-icon";
import { Button, Card, EmptyState, Input, LoadingPanel } from "@/components/ui";
import {
  buildTransportSpec,
  DEFAULT_HANDOFF_MODE,
  HANDOFF_MODES,
  type HandoffMode,
} from "@/lib/handoff-modes";
import {
  missingRequiredParams,
  resolvedParamFields,
  validateArtifactParams,
} from "@/lib/artifact-params";
import {
  api,
  createProfile,
  getProfile,
  previewAcquisitionKit,
  updateProfile,
  BACKEND_UNREACHABLE,
  type CollectionProfile,
} from "@/lib/api";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { ACQUIRE_PLATFORM_LABELS, ACQUIRE_PLATFORMS, artifactIconCloud, compareCollectorCategories, isAcquirePlatform, type AcquirePlatform } from "@/lib/catalog";
import {
  DEFAULT_GCP_LOG_BACKEND_FORM,
  cartNeedsGcpLogBackend,
  gcpConfigToForm,
  validateGcpLogBackendForm,
  type GcpLogBackendFormState,
} from "@/lib/gcp-log-backend";
import { GcpLogBackendFields } from "@/components/gcp-log-backend-fields";
import {
  isEnterpriseProfile,
  isPlatformProfile,
  parseDeploymentProfile,
  type DeploymentProfile,
} from "@/lib/deployment-profiles";
import { downloadTextFile } from "@/lib/download";
import {
  buildRequestBody,
  splitScope,
} from "@/lib/acquisition-build";
import { displayCategoryLabel } from "@/lib/format";
import { COLLECTION_KITS_HREF } from "@/lib/routes";
import type { Artifact } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  Check,
  ChevronDown,
  ChevronRight,
  Download,
  FileJson,
  PackageOpen,
  Save,
  Search,
  Settings2,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

function parseAcquirePlatform(raw: string | null): AcquirePlatform {
  const c = (raw || "aws").toLowerCase();
  return isAcquirePlatform(c) ? c : "aws";
}

function KitSectionTitle({ children }: { children: ReactNode }) {
  return <p className="text-sm font-semibold text-accent">{children}</p>;
}

function KitFieldLabel({ children }: { children: ReactNode }) {
  return <span className="text-sm font-medium text-fg">{children}</span>;
}

const KIT_INPUT_CLASS = "acquire-kit-input";

const KIT_OPTION_CARD = (selected: boolean) =>
  cn("acquire-option-card", selected && "is-selected");

function KitOptionCard({
  selected,
  onSelect,
  title,
  summary,
  groupName,
}: {
  selected: boolean;
  onSelect: () => void;
  title: string;
  summary: string;
  groupName: string;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      name={groupName}
      className={cn(KIT_OPTION_CARD(selected), "w-full text-left")}
      onClick={onSelect}
    >
      <span className="flex min-w-0 flex-1 gap-3">
        <span
          className={cn(
            "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border",
            selected ? "border-accent bg-accent" : "border-border bg-surface-2",
          )}
          aria-hidden
        >
          {selected && <span className="h-1.5 w-1.5 rounded-full bg-accent-fg" />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-fg">{title}</span>
          <span className="mt-1 block text-xs leading-relaxed text-fg">{summary}</span>
        </span>
      </span>
    </button>
  );
}

function artifactParamsFromProfile(
  raw?: Record<string, Record<string, unknown>>,
): Record<string, ParamValues> {
  if (!raw) return {};
  const out: Record<string, ParamValues> = {};
  for (const [collector, params] of Object.entries(raw)) {
    const values: ParamValues = {};
    for (const [key, val] of Object.entries(params)) {
      if (typeof val === "boolean") values[key] = val;
      else if (typeof val === "string") values[key] = val;
      else if (Array.isArray(val)) values[key] = val.map(String);
      else if (val != null) values[key] = String(val);
    }
    out[collector] = values;
  }
  return out;
}

function applyProfileToState(
  profile: CollectionProfile,
  all: Artifact[],
  setters: {
    setSince: (v: string) => void;
    setUntil: (v: string) => void;
    setRegions: (v: string) => void;
    setProjectIds: (v: string[]) => void;
    setSubscriptionIds: (v: string[]) => void;
    setAzureTenantId: (v: string) => void;
    setAzureClientId: (v: string) => void;
    setCart: (v: Set<string>) => void;
    setDeploymentProfile: (v: DeploymentProfile) => void;
    setMaxRecordsPerSource: (v: string) => void;
    setGcpLogBackend: (v: GcpLogBackendFormState) => void;
    setArtifactParams: (v: Record<string, ParamValues>) => void;
  },
) {
  const valid = new Set(all.map((a) => a.collector));
  setters.setSince(profile.since || "");
  setters.setUntil(profile.until || "");
  setters.setRegions((profile.regions || []).join(","));
  setters.setProjectIds(splitScope(profile.project));
  setters.setSubscriptionIds(splitScope(profile.subscription));
  setters.setAzureTenantId(profile.azure_tenant_id || "");
  setters.setAzureClientId(profile.azure_client_id || "");
  setters.setCart(new Set((profile.artifacts || []).filter((c) => valid.has(c))));
  setters.setDeploymentProfile(parseDeploymentProfile(profile.deployment_profile));
  setters.setMaxRecordsPerSource(
    profile.max_records_per_source != null ? String(profile.max_records_per_source) : "",
  );
  setters.setArtifactParams(artifactParamsFromProfile(profile.artifact_parameters));
  if (profile.gcp_log_backend) {
    setters.setGcpLogBackend(gcpConfigToForm(profile.gcp_log_backend));
  }
}

function AcquireContent() {
  const router = useRouter();
  const qc = useQueryClient();
  const searchParams = useSearchParams();
  const urlCaseId = searchParams.get("case_id")?.trim() || "";
  const urlCloud = parseAcquirePlatform(searchParams.get("cloud"));
  const urlProfileId = searchParams.get("profile")?.trim() || "";
  const urlCollectors = useMemo(
    () =>
      (searchParams.get("collectors") || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    [searchParams],
  );
  const prefillDone = useRef(false);
  const profileHydratedRef = useRef<string | null>(null);

  const [platform, setPlatform] = useState<AcquirePlatform>(() =>
    urlProfileId ? "aws" : urlCloud,
  );
  const [search, setSearch] = useState("");
  const [cart, setCart] = useState<Set<string>>(() => new Set(urlCollectors));
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [regions, setRegions] = useState("");
  const [projectIds, setProjectIds] = useState<string[]>([]);
  const [subscriptionIds, setSubscriptionIds] = useState<string[]>([]);
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureClientId, setAzureClientId] = useState("");
  const [maxRecordsPerSource, setMaxRecordsPerSource] = useState("");
  const [artifactParams, setArtifactParams] = useState<Record<string, ParamValues>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [deploymentProfile, setDeploymentProfile] = useState<DeploymentProfile>("platform");
  const [handoffMode, setHandoffMode] = useState<HandoffMode>(DEFAULT_HANDOFF_MODE);
  const [s3Bucket, setS3Bucket] = useState("");
  const [s3Prefix, setS3Prefix] = useState("cases");
  const [presignedUrl, setPresignedUrl] = useState("");
  const [error, setError] = useState("");
  const [iamPreview, setIamPreview] = useState<Awaited<ReturnType<typeof previewAcquisitionKit>> | null>(
    null,
  );
  const [iamPreviewError, setIamPreviewError] = useState("");
  const [iamActionsOpen, setIamActionsOpen] = useState(false);
  const [gcpLogBackend, setGcpLogBackend] = useState<GcpLogBackendFormState>(
    DEFAULT_GCP_LOG_BACKEND_FORM,
  );
  const [kitName, setKitName] = useState("");
  const [editProfile, setEditProfile] = useState<CollectionProfile | null>(null);
  const [kitSaved, setKitSaved] = useState(false);
  const isEditingKit = !!urlProfileId;

  const artifacts = useQuery({
    queryKey: ["artifacts", platform],
    queryFn: () => api.artifacts(platform),
    staleTime: 0,
    retry: 2,
    retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 4000),
  });

  const all = useMemo(
    () => (artifacts.data?.artifacts ?? []).filter((a) => a.selectable !== false),
    [artifacts.data?.artifacts],
  );

  useEffect(() => {
    if (prefillDone.current || !all.length) return;
    if (urlProfileId) return;
    prefillDone.current = true;
    if (urlCloud) setPlatform(urlCloud);
    if (urlCollectors.length) {
      const valid = new Set(all.map((a) => a.collector));
      setCart(new Set(urlCollectors.filter((c) => valid.has(c))));
    }
  }, [all, urlCloud, urlCollectors, urlProfileId]);

  useEffect(() => {
    profileHydratedRef.current = null;
    setEditProfile(null);
    if (!urlProfileId) {
      setKitName("");
      return;
    }
    let cancelled = false;
    getProfile(urlProfileId)
      .then((profile) => {
        if (cancelled) return;
        setKitName(profile.name);
        setEditProfile(profile);
        setPlatform(parseAcquirePlatform(profile.cloud));
      })
      .catch((e: Error) => setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [urlProfileId]);

  useEffect(() => {
    if (!editProfile || !all.length) return;
    if (parseAcquirePlatform(editProfile.cloud) !== platform) return;
    if (profileHydratedRef.current === editProfile.id) return;
    applyProfileToState(editProfile, all, {
      setSince,
      setUntil,
      setRegions,
      setProjectIds,
      setSubscriptionIds,
      setAzureTenantId,
      setAzureClientId,
      setCart,
      setDeploymentProfile,
      setMaxRecordsPerSource,
      setGcpLogBackend,
      setArtifactParams,
    });
    profileHydratedRef.current = editProfile.id;
    prefillDone.current = true;
  }, [editProfile, all, platform]);

  useEffect(() => {
    if (urlProfileId) return;
    const mode = searchParams.get("mode")?.trim().toLowerCase();
    if (mode === "run") setDeploymentProfile("platform");
  }, [urlProfileId, searchParams]);

  const fromCase = !!urlCaseId;
  const preselectedCount = urlCollectors.length;

  // Hide redundant subset collectors from the picker: each declares `subset_of` a broader
  // collector that already captures the exact same rows (e.g. bigquery_audit / secret_manager /
  // storage_access / login_events → cloud_audit_data; cloud_cdn / cloud_armor → load_balancer).
  // Listing both only tempts double-selection. The subsets remain available via the CLI/API for
  // targeted, smaller-output triage pulls.
  const selectable = useMemo(() => all.filter((a) => !a.subset_of), [all]);

  const visible = useMemo(() => {
    const s = search.trim().toLowerCase();
    if (!s) return selectable;
    return selectable.filter(
      (a) =>
        a.name.toLowerCase().includes(s) ||
        a.collector.toLowerCase().includes(s) ||
        a.description.toLowerCase().includes(s) ||
        a.category.toLowerCase().includes(s),
    );
  }, [selectable, search]);

  // Flat list grouped by domain category.
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

  const needsGcpLogBackend = platform === "gcp" && cartNeedsGcpLogBackend(collectors);
  const gcpLogBackendError = useMemo(
    () => validateGcpLogBackendForm(gcpLogBackend, needsGcpLogBackend),
    [gcpLogBackend, needsGcpLogBackend],
  );

  const transportSpec = useMemo(() => {
    if (!isEnterpriseProfile(deploymentProfile)) return "";
    return buildTransportSpec(handoffMode, s3Bucket, s3Prefix, presignedUrl);
  }, [deploymentProfile, handoffMode, s3Bucket, s3Prefix, presignedUrl]);

  const requestBody = useMemo(
    () =>
      buildRequestBody(
        platform,
        "",
        collectors,
        since,
        until,
        regions,
        projectIds,
        subscriptionIds,
        azureTenantId,
        azureClientId,
        "",
        artifactParams,
        cartForCloud,
        deploymentProfile,
        maxRecordsPerSource,
        isEnterpriseProfile(deploymentProfile) ? transportSpec : undefined,
        gcpLogBackend,
      ),
    [
      platform,
      collectors,
      since,
      until,
      regions,
      projectIds,
      subscriptionIds,
      azureTenantId,
      azureClientId,
      maxRecordsPerSource,
      artifactParams,
      cartForCloud,
      deploymentProfile,
      transportSpec,
      gcpLogBackend,
    ],
  );

  useEffect(() => {
    if (!collectors.length || isEditingKit) {
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
  }, [requestBody, collectors.length, isEditingKit]);

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

  const clear = () => setCart(new Set());

  const downloadIamPreview = () => {
    if (!iamPreview?.iam_policies) return;
    for (const [name, policy] of Object.entries(iamPreview.iam_policies)) {
      downloadTextFile(`preview-${name}`, JSON.stringify(policy, null, 2) + "\n", "application/json");
    }
  };

  const saveKitMut = useMutation({
    mutationFn: () => {
      const name = kitName.trim();
      const { case_id: _omit, ...kitPayload } = requestBody;
      if (isEditingKit) {
        return updateProfile(urlProfileId, { name, ...kitPayload, case_id: "" });
      }
      return createProfile({ name, ...kitPayload });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["config", "profiles"] });
      if (urlProfileId) {
        router.push(COLLECTION_KITS_HREF);
        return;
      }
      setKitSaved(true);
      setError("");
      window.setTimeout(() => setKitSaved(false), 2500);
    },
    onError: (e: Error) => setError(e.message || `Failed to ${isEditingKit ? "update" : "save"} kit`),
  });

  const saveKit = () => {
    if (!kitName.trim()) {
      setError("Enter a kit name before saving.");
      return;
    }
    if (cartForCloud.length === 0) {
      setError("Add at least one collector before saving a kit.");
      return;
    }
    const gcpLogErr = validateGcpLogBackendForm(gcpLogBackend, needsGcpLogBackend);
    if (gcpLogErr) {
      setError(gcpLogErr);
      return;
    }
    saveKitMut.mutate();
  };

  const tabs = ACQUIRE_PLATFORMS.map((c) => ({ id: c, label: ACQUIRE_PLATFORM_LABELS[c] }));
  const iconCloud = artifactIconCloud(platform);

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
    <div className="px-6 py-8">
      <div className="mb-6">
        {isEditingKit ? (
          <div className="flex items-start gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-border bg-bg">
              <CloudProviderIcon cloud={platform} />
            </span>
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                Edit collection kit · {ACQUIRE_PLATFORM_LABELS[platform]}
              </p>
              <h1 className="page-title mt-1.5 min-w-0">
                <span className="min-w-0 truncate">{kitName.trim() || "Untitled kit"}</span>
              </h1>
            </div>
          </div>
        ) : (
          <h1 className="page-title">
            <PackageOpen className="h-5 w-5 text-accent" />
            Acquire
          </h1>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_24rem]">
        {fromCase && preselectedCount > 0 && (
          <div className="lg:col-span-2 rounded-lg border border-accent/30 bg-accent/5 px-4 py-3 text-xs text-fg">
            Pre-selected <span className="mono font-medium">{preselectedCount}</span> missing log
            source{preselectedCount === 1 ? "" : "s"} for case{" "}
            <span className="mono font-medium">{urlCaseId}</span>. Adjust the kit, then{" "}
            {isPlatformProfile(deploymentProfile)
              ? "save the kit, then run it from Collection Kits."
              : "save the kit, then download it from Collection Kits."}
          </div>
        )}
        <div className="min-w-0">
          {!isEditingKit && (
            <div className="mb-4 flex items-center gap-1 border-b border-border">
              {tabs.map((t) => {
                const active = platform === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setPlatform(t.id)}
                    className={cn(
                      "relative -mb-px flex items-center gap-2 px-4 py-2.5 text-sm transition-colors",
                      active ? "text-fg" : "text-fg-subtle hover:text-fg",
                    )}
                  >
                    <CloudProviderIcon cloud={t.id} />
                    {t.label}
                    {active && (
                      <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-accent" />
                    )}
                  </button>
                );
              })}
            </div>
          )}

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

          {needsGcpLogBackend && (
            <GcpLogBackendFields
              form={gcpLogBackend}
              onChange={setGcpLogBackend}
              required={needsGcpLogBackend}
            />
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
                    : BACKEND_UNREACHABLE
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
                  <div className="space-y-2">
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
                            "acquire-collector-row overflow-hidden",
                            selected && "is-selected",
                            paramsExpanded && "is-expanded",
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
                            className="flex cursor-pointer items-center gap-3 py-2.5 pl-3 pr-3 text-left"
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
                            <ArtifactIcon cloud={iconCloud} collector={a.collector} size={24} />
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
                            </div>
                            <ArtifactInfoButton collector={a.collector} cloud={platform} />
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
                            <div className="px-4 pb-4 pt-3">
                              {renderParamHints(a)}
                              <AcquireParamFields
                                compact
                                className={missing.length > 0 ? "mt-3" : undefined}
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

        <aside className="lg:sticky lg:top-8 lg:self-start">
          <div className="acquire-kit-panel">
            <div className="acquire-kit-panel-header">
              <h3 className="flex items-center gap-2 text-sm font-semibold">
                <Download className="h-4 w-4 text-accent" /> Collection kit
              </h3>
            </div>

            <div className="acquire-kit-body">
              {cartForCloud.length === 0 ? (
                <p className="py-2 text-sm text-fg-subtle">Pick artifacts on the left to add them to the kit.</p>
              ) : (
                <div className="flex items-center justify-between gap-2 text-sm">
                  <span className="text-fg-subtle">
                    <span className="font-medium text-fg">{cartForCloud.length}</span> artifact
                    {cartForCloud.length === 1 ? "" : "s"} selected
                  </span>
                  <button
                    type="button"
                    onClick={clear}
                    className="inline-flex shrink-0 items-center gap-1 text-2xs text-fg-subtle hover:text-bad-red"
                  >
                    <Trash2 className="h-3 w-3" /> Clear all
                  </button>
                </div>
              )}

              <div className="acquire-kit-section">
                <label className="block space-y-1.5">
                  <KitFieldLabel>Kit name</KitFieldLabel>
                  <Input
                    value={kitName}
                    onChange={(e) => setKitName(e.target.value)}
                    placeholder="e.g. AWS production baseline"
                    className={KIT_INPUT_CLASS}
                  />
                </label>
              </div>

              {isEnterpriseProfile(deploymentProfile) && (
                <div className="acquire-kit-section">
                  <KitSectionTitle>Evidence handoff</KitSectionTitle>
                  <div className="space-y-2" role="radiogroup" aria-label="Evidence handoff">
                    {HANDOFF_MODES.map((mode) => (
                      <KitOptionCard
                        key={mode.id}
                        groupName="handoff_mode"
                        selected={handoffMode === mode.id}
                        onSelect={() => setHandoffMode(mode.id)}
                        title={mode.label}
                        summary={mode.summary}
                      />
                    ))}
                  </div>

                  {handoffMode === "s3_ir_bucket" && (
                    <>
                      <p className="text-xs leading-relaxed text-fg">
                        Your Ventra server must be able to read this bucket (Import from S3 uses
                        server-side AWS credentials, not the client browser).
                      </p>
                      <label className="block space-y-1.5">
                        <KitFieldLabel>Your IR bucket</KitFieldLabel>
                        <Input
                          value={s3Bucket}
                          onChange={(e) => setS3Bucket(e.target.value)}
                          placeholder="ir-evidence-bucket"
                          className={cn("mono", KIT_INPUT_CLASS)}
                        />
                      </label>
                      <label className="block space-y-1.5">
                        <KitFieldLabel>Prefix</KitFieldLabel>
                        <Input
                          value={s3Prefix}
                          onChange={(e) => setS3Prefix(e.target.value)}
                          placeholder="cases"
                          className={cn("mono", KIT_INPUT_CLASS)}
                        />
                      </label>
                    </>
                  )}

                  {handoffMode === "presigned" && (
                    <>
                      <p className="text-xs leading-relaxed text-fg">
                        Generate a presigned PUT URL in your IR bucket, paste it here, and send
                        the kit to the client. After upload, ingest from your bucket.
                      </p>
                      <label className="block space-y-1.5">
                        <KitFieldLabel>Presigned PUT URL</KitFieldLabel>
                        <Input
                          value={presignedUrl}
                          onChange={(e) => setPresignedUrl(e.target.value)}
                          placeholder="https://bucket.s3.amazonaws.com/key?X-Amz-..."
                          className={cn("mono", KIT_INPUT_CLASS)}
                        />
                      </label>
                    </>
                  )}

                  {transportSpec && (
                    <p className="mono text-xs text-accent">{transportSpec}</p>
                  )}
                </div>
              )}

              {!isEditingKit && (
              <div className="acquire-kit-section">
                <KitSectionTitle>Global collection window</KitSectionTitle>
                <div className="grid grid-cols-2 gap-2">
                  <label className="block space-y-1.5">
                    <KitFieldLabel>Since</KitFieldLabel>
                    <Input
                      value={since}
                      onChange={(e) => setSince(e.target.value)}
                      placeholder="2026-05-01"
                      className={KIT_INPUT_CLASS}
                    />
                  </label>
                  <label className="block space-y-1.5">
                    <KitFieldLabel>Until</KitFieldLabel>
                    <Input
                      value={until}
                      onChange={(e) => setUntil(e.target.value)}
                      placeholder="2026-06-01"
                      className={KIT_INPUT_CLASS}
                    />
                  </label>
                </div>
                <label className="block space-y-1.5">
                  <KitFieldLabel>Regions</KitFieldLabel>
                  <Input
                    value={regions}
                    onChange={(e) => setRegions(e.target.value)}
                    placeholder={platform === "aws" ? "us-east-1,us-west-2" : "optional"}
                    className={KIT_INPUT_CLASS}
                  />
                </label>
                {platform === "gcp" && (
                  <div className="block space-y-1.5">
                    <KitFieldLabel>Project ID(s)</KitFieldLabel>
                    <MultiValueInput
                      items={projectIds}
                      placeholder="my-project"
                      onChange={setProjectIds}
                    />
                  </div>
                )}
                {platform === "azure" && (
                  <>
                    <div className="block space-y-1.5">
                      <KitFieldLabel>Subscription ID(s)</KitFieldLabel>
                      <MultiValueInput
                        items={subscriptionIds}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        onChange={setSubscriptionIds}
                      />
                    </div>
                    <label className="block space-y-1.5">
                      <KitFieldLabel>Entra tenant ID (optional)</KitFieldLabel>
                      <Input
                        value={azureTenantId}
                        onChange={(e) => setAzureTenantId(e.target.value)}
                        placeholder="Embedded in acquisition.yaml — or use AZURE_TENANT_ID"
                        className={cn("mono", KIT_INPUT_CLASS)}
                      />
                    </label>
                    <label className="block space-y-1.5">
                      <KitFieldLabel>App client ID (optional)</KitFieldLabel>
                      <Input
                        value={azureClientId}
                        onChange={(e) => setAzureClientId(e.target.value)}
                        placeholder="Embedded in acquisition.yaml — or use AZURE_CLIENT_ID"
                        className={cn("mono", KIT_INPUT_CLASS)}
                      />
                    </label>
                    <p className="text-xs leading-relaxed text-fg">
                      Set <span className="mono">AZURE_CLIENT_SECRET</span> in the environment before
                      running <span className="mono">ventra.py</span> — never put secrets in the kit zip.
                    </p>
                  </>
                )}
                <label className="block space-y-1.5">
                  <KitFieldLabel>Records count to collect (optional)</KitFieldLabel>
                  <Input
                    type="number"
                    min={0}
                    step={1}
                    value={maxRecordsPerSource}
                    onChange={(e) => setMaxRecordsPerSource(e.target.value)}
                    placeholder="Unlimited"
                    className={cn("mono", KIT_INPUT_CLASS)}
                  />
                </label>
              </div>
              )}

              {!isEditingKit && (
              <div className="acquire-kit-section">
                <div className="flex items-center gap-2 text-sm font-semibold text-accent">
                  <ShieldCheck className="h-4 w-4" />
                  Read-only IAM policy
                </div>
                {collectors.length > 0 && (
                  <div className="acquire-kit-iam-box">
                    {iamPreviewError ? (
                      <p className="text-xs text-bad-red">{iamPreviewError}</p>
                    ) : iamPreview ? (
                      <>
                        <p className="text-sm text-fg">
                          <span className="mono font-semibold">{iamPreview.iam_action_count}</span> IAM
                          action{iamPreview.iam_action_count === 1 ? "" : "s"}
                          {iamPreview.implicit_collectors.length > 0 && (
                            <span className="text-fg">
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
              )}

              {error && <p className="text-xs text-bad-red">{error}</p>}

              {!isEditingKit && needsGcpLogBackend && gcpLogBackendError && (
                <p className="text-xs text-warn-amber">{gcpLogBackendError}</p>
              )}

              <div className="acquire-kit-actions">
                <Button
                  variant="primary"
                  icon={kitSaved ? Check : Save}
                  className="w-full justify-center"
                  disabled={cartForCloud.length === 0 || saveKitMut.isPending}
                  loading={saveKitMut.isPending}
                  onClick={saveKit}
                >
                  {kitSaved ? (isEditingKit ? "Kit updated" : "Kit saved") : isEditingKit ? "Update kit" : "Save kit"}
                </Button>
                {kitSaved && (
                  <p className="text-center text-xs text-fg-subtle">
                    View in{" "}
                    <Link href={COLLECTION_KITS_HREF} className="text-accent hover:underline">
                      Collection Kits
                    </Link>
                  </p>
                )}
              </div>
            </div>
          </div>
        </aside>
      </div>

      <IamActionsDialog
        open={iamActionsOpen}
        onClose={() => setIamActionsOpen(false)}
        cloud={platform}
        actions={iamPreview?.iam_actions ?? []}
        actionCount={iamPreview?.iam_action_count ?? 0}
        implicitCount={iamPreview?.implicit_collectors.length ?? 0}
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
