"use client";

import { MultiValueInput } from "@/components/acquire-param-fields";
import { GcpLogBackendFields } from "@/components/gcp-log-backend-fields";
import { IamActionsDialog } from "@/components/iam-actions-dialog";
import { ProviderSelector } from "@/components/provider-selector";
import { Button, Input } from "@/components/ui";
import { WizardLayout } from "@/components/wizard-layout";
import { api, previewAcquisitionKit, type CollectionProfile } from "@/lib/api";
import {
  buildKitRunRequest,
  scopeStateFromProfile,
  type KitRunScopeState,
} from "@/lib/acquisition-build";
import { ACQUIRE_PLATFORM_LABELS, CASE_PLATFORM_LABELS, acquirePermissionModel, isAcquirePlatform } from "@/lib/catalog";
import { displayCaseId, validateCaseId } from "@/lib/case-id";
import { downloadTextFile } from "@/lib/download";
import {
  cartNeedsGcpLogBackend,
  validateGcpLogBackendForm,
} from "@/lib/gcp-log-backend";
import { readLastConnection } from "@/lib/provider-storage";
import type { CaseSummary } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { Check, ChevronDown, FileJson, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";

type CaseMode = "existing" | "new";

type WizardStep = "case" | "auth" | "scope" | "iam";

function wizardSteps(platform: string) {
  const model = acquirePermissionModel(platform);
  return [
    { id: "case" as const, label: "Case", description: "Choose destination" },
    { id: "auth" as const, label: "Authentication", description: "Link credentials" },
    { id: "scope" as const, label: "Time & scope", description: "Collection window" },
    { id: "iam" as const, label: `${model} policy`, description: "Review permissions" },
  ];
}

type Props = {
  open: boolean;
  kit: CollectionProfile | null;
  onClose: () => void;
  onConfirm: (payload: { caseId: string; connectionId: string; scope: KitRunScopeState }) => void;
  running?: boolean;
  error?: string;
};

const GLASS_TRIGGER =
  "box-border flex h-9 w-full items-center justify-between gap-2 rounded-md border border-white/10 bg-surface/80 px-3 text-left text-sm leading-none text-fg shadow-[0_1px_0_rgb(255_255_255/0.06)_inset] backdrop-blur transition-colors hover:bg-surface/90 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:cursor-not-allowed disabled:opacity-50";

const GLASS_MENU =
  "z-[400] min-w-[10rem] animate-fade-in overflow-hidden rounded-md border border-white/10 bg-surface/95 p-1 shadow-[0_12px_40px_-16px_rgb(0_0_0/0.75)] backdrop-blur";

const KIT_INPUT_CLASS = "acquire-kit-input";

function platformLabel(cloud: string): string {
  const key = cloud.toLowerCase();
  return (
    ACQUIRE_PLATFORM_LABELS[key as keyof typeof ACQUIRE_PLATFORM_LABELS]
    ?? CASE_PLATFORM_LABELS[key as keyof typeof CASE_PLATFORM_LABELS]
    ?? cloud
  );
}

function CaseSelector({
  cases,
  value,
  onChange,
  disabled,
  loading,
  emptyLabel,
}: {
  cases: CaseSummary[];
  value: string;
  onChange: (caseId: string) => void;
  disabled?: boolean;
  loading?: boolean;
  emptyLabel: string;
}) {
  const [open, setOpen] = useState(false);
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLUListElement>(null);

  const selected = cases.find((c) => c.case_id === value);

  const updateMenuPos = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    setMenuPos({
      top: rect.bottom + 4,
      left: rect.left,
      width: Math.max(rect.width, 200),
    });
  }, []);

  useLayoutEffect(() => {
    if (!open) {
      setMenuPos(null);
      return;
    }
    updateMenuPos();
  }, [open, updateMenuPos]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const target = e.target as Node;
      if (triggerRef.current?.contains(target) || menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onReposition = () => updateMenuPos();
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", onReposition);
    window.addEventListener("scroll", onReposition, true);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", onReposition);
      window.removeEventListener("scroll", onReposition, true);
    };
  }, [open, updateMenuPos]);

  const pick = (caseId: string) => {
    onChange(caseId);
    setOpen(false);
  };

  const menu =
    open && menuPos && typeof document !== "undefined"
      ? createPortal(
          <ul
            ref={menuRef}
            role="listbox"
            className={GLASS_MENU}
            style={{
              position: "fixed",
              top: menuPos.top,
              left: menuPos.left,
              width: menuPos.width,
            }}
          >
            {cases.map((c) => {
              const active = c.case_id === value;
              return (
                <li key={c.case_id} role="option" aria-selected={active}>
                  <button
                    type="button"
                    onClick={() => pick(c.case_id)}
                    className={cn(
                      "flex w-full items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-left text-sm transition-colors hover:bg-white/5",
                      active ? "text-fg" : "text-fg-subtle",
                    )}
                  >
                    <span className="truncate">{displayCaseId(c.case_id)}</span>
                    {active && <Check className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />}
                  </button>
                </li>
              );
            })}
          </ul>,
          document.body,
        )
      : null;

  if (loading) {
    return <p className="text-xs text-fg-subtle">Loading cases…</p>;
  }

  if (cases.length === 0) {
    return <p className="text-xs text-fg-subtle">{emptyLabel}</p>;
  }

  return (
    <div className="relative">
      <button
        ref={triggerRef}
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={GLASS_TRIGGER}
      >
        <span className={cn("min-w-0 truncate", !selected && "text-fg-subtle")}>
          {selected ? displayCaseId(selected.case_id) : "Select case"}
        </span>
        <ChevronDown
          className={cn("h-3.5 w-3.5 shrink-0 opacity-60 transition-transform", open && "rotate-180")}
        />
      </button>
      {menu}
    </div>
  );
}

export function KitRunWizard({ open, kit, onClose, onConfirm, running, error }: Props) {
  const [step, setStep] = useState<WizardStep>("case");
  const [caseMode, setCaseMode] = useState<CaseMode>("existing");
  const [existingCaseId, setExistingCaseId] = useState("");
  const [newCaseId, setNewCaseId] = useState("");
  const [connectionId, setConnectionId] = useState("");
  const [scope, setScope] = useState<KitRunScopeState>(() => scopeStateFromProfile({ cloud: "aws" } as CollectionProfile));
  const [localError, setLocalError] = useState("");
  const [iamPreview, setIamPreview] = useState<Awaited<ReturnType<typeof previewAcquisitionKit>> | null>(null);
  const [iamPreviewError, setIamPreviewError] = useState("");
  const [iamActionsOpen, setIamActionsOpen] = useState(false);

  const cloud = kit?.cloud ?? "aws";
  const platformKey = cloud.toLowerCase();
  const platform = isAcquirePlatform(platformKey) ? platformKey : platformKey === "m365" ? "m365" : "aws";
  const providerLabel = platformLabel(cloud);
  const collectors = kit?.artifacts ?? [];
  const steps = useMemo(() => wizardSteps(platform), [platform]);
  const needsGcpLogBackend = platform === "gcp" && cartNeedsGcpLogBackend(collectors);
  const gcpLogBackendError = useMemo(
    () => validateGcpLogBackendForm(scope.gcpLogBackend, needsGcpLogBackend),
    [scope.gcpLogBackend, needsGcpLogBackend],
  );

  const cases = useQuery({
    queryKey: ["cases"],
    queryFn: api.cases,
    enabled: open,
    staleTime: 30_000,
  });

  const caseOptions = useMemo(
    () => (cases.data?.cases ?? []).filter((c) => c.cloud.toLowerCase() === cloud.toLowerCase()),
    [cases.data?.cases, cloud],
  );

  const resolvedCaseId = caseMode === "existing" ? existingCaseId.trim() : newCaseId.trim();

  const requestBody = useMemo(() => {
    if (!kit || !resolvedCaseId) return null;
    const check = validateCaseId(resolvedCaseId);
    if (!check.ok) return null;
    return buildKitRunRequest(kit, check.normalized, scope);
  }, [kit, resolvedCaseId, scope]);

  useEffect(() => {
    if (!open || !kit) return;
    setStep("case");
    setCaseMode(caseOptions.length ? "existing" : "new");
    setExistingCaseId(caseOptions[0]?.case_id ?? "");
    setNewCaseId("");
    setConnectionId(readLastConnection() ?? "");
    setScope(scopeStateFromProfile(kit));
    setLocalError("");
    setIamPreview(null);
    setIamPreviewError("");
    setIamActionsOpen(false);
  }, [open, kit, caseOptions]);

  useEffect(() => {
    if (step !== "iam" || !requestBody) {
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
  }, [step, requestBody]);

  if (!open || !kit) return null;

  const patchScope = (patch: Partial<KitRunScopeState>) => setScope((prev) => ({ ...prev, ...patch }));

  const validateCaseStep = (): string | null => {
    if (caseMode === "existing") {
      if (!existingCaseId.trim()) return "Select a case to run against.";
      return null;
    }
    const check = validateCaseId(newCaseId);
    if (!check.ok) return check.message;
    return null;
  };

  const validateAuthStep = (): string | null => {
    if (!connectionId.trim()) return "Select an authentication connection.";
    return null;
  };

  const validateScopeStep = (): string | null => {
    const capRaw = scope.maxRecordsPerSource.trim();
    if (capRaw) {
      const cap = Number(capRaw);
      if (!Number.isFinite(cap) || cap < 0 || !Number.isInteger(cap)) {
        return "Records count to collect must be a whole number.";
      }
    }
    if (gcpLogBackendError) return gcpLogBackendError;
    return null;
  };

  const goNext = () => {
    setLocalError("");
    if (step === "case") {
      const err = validateCaseStep();
      if (err) {
        setLocalError(err);
        return;
      }
      setStep("auth");
      return;
    }
    if (step === "auth") {
      const err = validateAuthStep();
      if (err) {
        setLocalError(err);
        return;
      }
      setStep("scope");
      return;
    }
    if (step === "scope") {
      const err = validateScopeStep();
      if (err) {
        setLocalError(err);
        return;
      }
      setStep("iam");
    }
  };

  const goBack = () => {
    setLocalError("");
    const idx = steps.findIndex((s) => s.id === step);
    if (idx > 0) setStep(steps[idx - 1].id);
  };

  const startRun = () => {
    setLocalError("");
    const caseErr = validateCaseStep();
    if (caseErr) {
      setLocalError(caseErr);
      setStep("case");
      return;
    }
    const authErr = validateAuthStep();
    if (authErr) {
      setLocalError(authErr);
      setStep("auth");
      return;
    }
    const scopeErr = validateScopeStep();
    if (scopeErr) {
      setLocalError(scopeErr);
      setStep("scope");
      return;
    }
    const check = validateCaseId(caseMode === "existing" ? existingCaseId : newCaseId);
    if (!check.ok) {
      setLocalError(check.message);
      setStep("case");
      return;
    }
    onConfirm({ caseId: check.normalized, connectionId: connectionId.trim(), scope });
  };

  const downloadIamPreview = () => {
    if (!iamPreview?.iam_policies) return;
    for (const [name, policy] of Object.entries(iamPreview.iam_policies)) {
      downloadTextFile(`preview-${name}`, JSON.stringify(policy, null, 2) + "\n", "application/json");
    }
  };

  const shownError = localError || error;
  const onLastStep = step === "iam";
  const currentIdx = steps.findIndex((s) => s.id === step);

  return (
    <>
      <WizardLayout
        open={open}
        onClose={onClose}
        closeDisabled={running}
        steps={steps}
        currentStepId={step}
        ariaLabel={`Run collection kit: ${kit.name}`}
        footer={
          <div className="flex items-center justify-between gap-3 px-5 py-4 sm:px-6">
            <p className="min-w-0 truncate text-xs text-bad-red">{shownError}</p>
            <div className="flex shrink-0 gap-2">
              {currentIdx > 0 && (
                <Button variant="secondary" onClick={goBack} disabled={running}>
                  Back
                </Button>
              )}
              {!onLastStep ? (
                <Button variant="primary" onClick={goNext} disabled={running}>
                  Continue
                </Button>
              ) : (
                <Button variant="primary" loading={running} disabled={running} onClick={startRun}>
                  Start run
                </Button>
              )}
            </div>
          </div>
        }
      >
        <div className="space-y-4">
            {step === "case" && (
              <>
                <div className="flex gap-2" role="radiogroup" aria-label="Case selection mode">
                  <button
                    type="button"
                    role="radio"
                    aria-checked={caseMode === "existing"}
                    disabled={caseOptions.length === 0 || running}
                    className={cn(
                      "flex-1 rounded-lg border px-3 py-2 text-left text-sm transition-colors",
                      caseMode === "existing"
                        ? "border-accent bg-accent/10 text-fg"
                        : "border-border bg-surface-2 text-fg-subtle hover:text-fg",
                      caseOptions.length === 0 && "cursor-not-allowed opacity-50",
                    )}
                    onClick={() => setCaseMode("existing")}
                  >
                    <span className="font-medium">Existing case</span>
                  </button>
                  <button
                    type="button"
                    role="radio"
                    aria-checked={caseMode === "new"}
                    disabled={running}
                    className={cn(
                      "flex-1 rounded-lg border px-3 py-2 text-left text-sm transition-colors",
                      caseMode === "new"
                        ? "border-accent bg-accent/10 text-fg"
                        : "border-border bg-surface-2 text-fg-subtle hover:text-fg",
                    )}
                    onClick={() => setCaseMode("new")}
                  >
                    <span className="font-medium">New case</span>
                  </button>
                </div>

                {caseMode === "existing" ? (
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Case</span>
                    <CaseSelector
                      cases={caseOptions}
                      value={existingCaseId}
                      onChange={setExistingCaseId}
                      disabled={running}
                      loading={cases.isLoading}
                      emptyLabel={`No ${providerLabel} cases yet — use New case to create one at run time.`}
                    />
                  </label>
                ) : (
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Case ID</span>
                    <Input
                      value={newCaseId}
                      onChange={(e) => setNewCaseId(e.target.value)}
                      placeholder="CASE-2026-0042"
                      disabled={running}
                      className={KIT_INPUT_CLASS}
                    />
                  </label>
                )}
              </>
            )}

            {step === "auth" && (
              <div className="space-y-3">
                <p className="text-sm text-fg-subtle">
                  Choose the {providerLabel} connection Ventra will use to collect evidence for this run.
                </p>
                <ProviderSelector
                  platform={cloud}
                  value={connectionId}
                  onChange={setConnectionId}
                  elevated
                />
              </div>
            )}

            {step === "scope" && (
              <div className="space-y-4">
                <p className="text-sm text-fg-subtle">
                  Set the collection window and scope for this run. Defaults come from the kit template where saved.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Since</span>
                    <Input
                      value={scope.since}
                      onChange={(e) => patchScope({ since: e.target.value })}
                      placeholder="2026-05-01"
                      disabled={running}
                      className={KIT_INPUT_CLASS}
                    />
                  </label>
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Until</span>
                    <Input
                      value={scope.until}
                      onChange={(e) => patchScope({ until: e.target.value })}
                      placeholder="2026-06-01"
                      disabled={running}
                      className={KIT_INPUT_CLASS}
                    />
                  </label>
                </div>

                {(platform === "aws" || platform === "gcp") && (
                  <label className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">
                      {platform === "aws" ? "Regions" : "Regions (optional)"}
                    </span>
                    <Input
                      value={scope.regions}
                      onChange={(e) => patchScope({ regions: e.target.value })}
                      placeholder={platform === "aws" ? "us-east-1,us-west-2" : "optional"}
                      disabled={running}
                      className={KIT_INPUT_CLASS}
                    />
                  </label>
                )}

                {platform === "gcp" && (
                  <div className="block space-y-1.5">
                    <span className="text-sm font-medium text-fg">Project ID(s)</span>
                    <MultiValueInput
                      items={scope.projectIds}
                      placeholder="my-project"
                      onChange={(projectIds) => patchScope({ projectIds })}
                    />
                  </div>
                )}

                {platform === "azure" && (
                  <>
                    <div className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">Subscription ID(s)</span>
                      <MultiValueInput
                        items={scope.subscriptionIds}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        onChange={(subscriptionIds) => patchScope({ subscriptionIds })}
                      />
                    </div>
                    <label className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">Entra tenant ID (optional)</span>
                      <Input
                        value={scope.azureTenantId}
                        onChange={(e) => patchScope({ azureTenantId: e.target.value })}
                        placeholder="Or use AZURE_TENANT_ID at runtime"
                        disabled={running}
                        className={cn("mono", KIT_INPUT_CLASS)}
                      />
                    </label>
                    <label className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">App client ID (optional)</span>
                      <Input
                        value={scope.azureClientId}
                        onChange={(e) => patchScope({ azureClientId: e.target.value })}
                        placeholder="Or use AZURE_CLIENT_ID at runtime"
                        disabled={running}
                        className={cn("mono", KIT_INPUT_CLASS)}
                      />
                    </label>
                  </>
                )}

                {platform === "m365" && (
                  <>
                    <label className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">Entra tenant ID (optional)</span>
                      <Input
                        value={scope.azureTenantId}
                        onChange={(e) => patchScope({ azureTenantId: e.target.value })}
                        placeholder="Or use AZURE_TENANT_ID at runtime"
                        disabled={running}
                        className={cn("mono", KIT_INPUT_CLASS)}
                      />
                    </label>
                    <label className="block space-y-1.5">
                      <span className="text-sm font-medium text-fg">App client ID (optional)</span>
                      <Input
                        value={scope.azureClientId}
                        onChange={(e) => patchScope({ azureClientId: e.target.value })}
                        placeholder="Or use AZURE_CLIENT_ID at runtime"
                        disabled={running}
                        className={cn("mono", KIT_INPUT_CLASS)}
                      />
                    </label>
                  </>
                )}

                <label className="block space-y-1.5">
                  <span className="text-sm font-medium text-fg">Records count to collect (optional)</span>
                  <Input
                    type="number"
                    min={0}
                    step={1}
                    value={scope.maxRecordsPerSource}
                    onChange={(e) => patchScope({ maxRecordsPerSource: e.target.value })}
                    placeholder="Unlimited"
                    disabled={running}
                    className={cn("mono", KIT_INPUT_CLASS)}
                  />
                </label>

                {needsGcpLogBackend && (
                  <GcpLogBackendFields
                    form={scope.gcpLogBackend}
                    onChange={(gcpLogBackend) => patchScope({ gcpLogBackend })}
                    required={needsGcpLogBackend}
                  />
                )}
              </div>
            )}

            {step === "iam" && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-accent">
                  <ShieldCheck className="h-4 w-4" />
                  Read-only {acquirePermissionModel(platform)} policy
                </div>
                <p className="text-sm text-fg-subtle">
                  Preview the narrowed permissions required for {collectors.length} collector
                  {collectors.length === 1 ? "" : "s"} in this kit.
                </p>
                <div className="rounded-lg border border-border bg-surface-2/50 p-4">
                  {iamPreviewError ? (
                    <p className="text-xs text-bad-red">{iamPreviewError}</p>
                  ) : iamPreview ? (
                    <>
                      <p className="text-sm text-fg">
                        <span className="mono font-semibold">{iamPreview.iam_action_count}</span>{" "}
                        {acquirePermissionModel(platform)} action
                        {iamPreview.iam_action_count === 1 ? "" : "s"}
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
                          Show {acquirePermissionModel(platform)} actions
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
                    <p className="text-xs text-fg-subtle">
                      Calculating {acquirePermissionModel(platform)} preview…
                    </p>
                  )}
                </div>
              </div>
            )}

        </div>
      </WizardLayout>

      <IamActionsDialog
        open={iamActionsOpen}
        onClose={() => setIamActionsOpen(false)}
        cloud={platform}
        actions={iamPreview?.iam_actions ?? []}
        actionCount={iamPreview?.iam_action_count ?? 0}
        implicitCount={iamPreview?.implicit_collectors.length ?? 0}
        elevated
      />
    </>
  );
}
