"use client";

import { Button } from "@/components/ui";
import {
  createConnection,
  testConnection,
  updateConnection,
  type Connection,
} from "@/lib/api";
import { gsap, matchMediaReduced, useGSAP } from "@/lib/gsap-client";
import { cn } from "@/lib/utils";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { validateAccessKeyId, validateGuid, validateGcpServiceAccountJson, validateKubeconfigContext, validateKubeconfigYaml, validateRoleArn } from "./provider-meta";
import { ProviderStepAuth } from "./provider-step-auth";
import { ProviderStepAuthMethod } from "./provider-step-auth-method";
import { ProviderStepDetails } from "./provider-step-details";
import { ProviderStepLink } from "./provider-step-link";
import {
  ProviderStepValidate,
  type ConnectionTestResult,
} from "./provider-step-validate";
import {
  EMPTY_WIZARD_DATA,
  WIZARD_STEPS,
  connectionToWizardData,
  defaultAuthMethodForPlatform,
  wizardDataToConnection,
  type ProviderPlatform,
  type ProviderWizardData,
  type WizardStepId,
} from "./types";

function stepIndex(id: WizardStepId): number {
  return WIZARD_STEPS.findIndex((s) => s.id === id);
}

/** True when required name + scope fields for the chosen platform are present and well-formed. */
function scopeComplete(data: ProviderWizardData): boolean {
  const { platform } = data;
  if (!platform) return false;
  if (!data.name.trim()) return false;
  if (platform === "gcp" && !data.project.trim()) return false;
  if (platform === "azure") {
    const sub = data.subscription.trim();
    if (!sub || validateGuid(sub, "Subscription")) return false;
  }
  if (platform === "m365" && !data.m365_domain.trim()) return false;
  if (platform === "kubernetes" && !data.k8s_context.trim()) return false;
  return true;
}

function awsAuthComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  if (data.auth_method === "assume_role") {
    const arn = data.role_arn.trim();
    if (!arn || validateRoleArn(arn)) return false;
    return true;
  }
  if (!data.aws_access_key_id.trim() || validateAccessKeyId(data.aws_access_key_id)) return false;
  if (!connectionId && !data.aws_secret_access_key.trim()) return false;
  return true;
}

function gcpAuthComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  if (data.auth_method === "adc") {
    return Boolean(data.project.trim());
  }
  const json = data.gcp_service_account_json.trim();
  if (!connectionId && !json) return false;
  if (json && validateGcpServiceAccountJson(json)) return false;
  return true;
}

function azureAuthComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  const tenant = data.azure_tenant_id.trim();
  const client = data.azure_client_id.trim();
  if (!tenant || validateGuid(tenant, "Tenant")) return false;
  if (!client || validateGuid(client, "Client")) return false;
  if (!connectionId && !data.azure_client_secret.trim()) return false;
  return true;
}

function m365AuthComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  const tenant = data.azure_tenant_id.trim();
  const client = data.azure_client_id.trim();
  if (!tenant || validateGuid(tenant, "Tenant")) return false;
  if (!client || validateGuid(client, "Client")) return false;
  if (data.auth_method === "certificate") {
    if (!connectionId && !data.azure_client_certificate_content.trim()) return false;
  } else if (!connectionId && !data.azure_client_secret.trim()) {
    return false;
  }
  return true;
}

function k8sAuthComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  const kubeconfig = data.kubeconfig_content.trim();
  if (!connectionId && !kubeconfig) return false;
  if (kubeconfig) {
    if (validateKubeconfigYaml(kubeconfig)) return false;
    if (validateKubeconfigContext(kubeconfig, data.k8s_context)) return false;
  }
  return true;
}

function wizardComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  if (!scopeComplete(data)) return false;
  if (data.platform === "aws" && !awsAuthComplete(data, connectionId)) return false;
  if (data.platform === "gcp" && !gcpAuthComplete(data, connectionId)) return false;
  if (data.platform === "azure" && !azureAuthComplete(data, connectionId)) return false;
  if (data.platform === "m365" && !m365AuthComplete(data, connectionId)) return false;
  if (data.platform === "kubernetes" && !k8sAuthComplete(data, connectionId)) return false;
  return true;
}

function authMethodSelected(data: ProviderWizardData): boolean {
  const { platform, auth_method } = data;
  if (!platform) return false;
  if (platform === "aws") return auth_method === "assume_role" || auth_method === "credentials";
  if (platform === "gcp") return auth_method === "service_account" || auth_method === "adc";
  if (platform === "azure") return auth_method === "service_principal";
  if (platform === "m365") return auth_method === "client_secret" || auth_method === "certificate";
  if (platform === "kubernetes") return auth_method === "kubeconfig";
  return false;
}

function authCredentialsComplete(data: ProviderWizardData, connectionId?: string | null): boolean {
  if (data.platform === "aws") return awsAuthComplete(data, connectionId);
  if (data.platform === "gcp") return gcpAuthComplete(data, connectionId);
  if (data.platform === "azure") return azureAuthComplete(data, connectionId);
  if (data.platform === "m365") return m365AuthComplete(data, connectionId);
  if (data.platform === "kubernetes") return k8sAuthComplete(data, connectionId);
  return true;
}

function canAdvanceFrom(
  step: WizardStepId,
  data: ProviderWizardData,
  connectionId?: string | null,
): boolean {
  if (step === "link") return Boolean(data.platform);
  if (step === "details") return scopeComplete(data);
  if (step === "auth_method") return scopeComplete(data) && authMethodSelected(data);
  if (step === "auth") {
    if (!scopeComplete(data) || !authMethodSelected(data)) return false;
    return authCredentialsComplete(data, connectionId);
  }
  return true;
}

export function ProviderWizard({
  open,
  onClose,
  editing,
}: {
  open: boolean;
  onClose: () => void;
  editing: Connection | null;
}) {
  const qc = useQueryClient();
  const dialogRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const stepperRef = useRef<HTMLElement>(null);
  const [step, setStep] = useState<WizardStepId>("link");
  const [data, setData] = useState<ProviderWizardData>(EMPTY_WIZARD_DATA);
  const [draftId, setDraftId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [tested, setTested] = useState(false);
  const [saveError, setSaveError] = useState("");

  const connectionId = editing?.id ?? draftId;

  const reset = useCallback(() => {
    setStep(editing ? "details" : "link");
    setData(editing ? connectionToWizardData(editing) : EMPTY_WIZARD_DATA);
    setDraftId(editing?.id ?? null);
    setTestResult(null);
    setTested(false);
    setSaveError("");
  }, [editing]);

  useEffect(() => {
    if (open) reset();
  }, [open, reset]);

  // Move focus into the active step when it changes (unless an autofocus field already claimed it).
  useEffect(() => {
    if (!open) return;
    const id = window.setTimeout(() => {
      const el = contentRef.current;
      if (!el || el.contains(document.activeElement)) return;
      el.querySelector<HTMLElement>("input:not([disabled]), button:not([disabled])")?.focus();
    }, 60);
    return () => window.clearTimeout(id);
  }, [step, open]);

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
          gsap.from(contentRef.current, {
            x: reduceMotion ? 0 : 16,
            autoAlpha: reduceMotion ? 1 : 0,
            duration: reduceMotion ? 0 : 0.24,
            ease: "power2.out",
          });
        },
        dialogRef,
      );
      return () => mm.revert();
    },
    { scope: dialogRef, dependencies: [step], revertOnUpdate: true },
  );

  const patchData = (patch: Partial<ProviderWizardData>) => {
    setData((prev) => ({ ...prev, ...patch }));
    setTestResult(null);
    setTested(false);
  };

  const ensureConnection = async (): Promise<string> => {
    const payload = wizardDataToConnection(data, {
      omitEmptySecret: Boolean(connectionId),
      omitEmptySessionToken: Boolean(connectionId),
      omitEmptyGcpKey: Boolean(connectionId),
      omitEmptyAzureSecret: Boolean(connectionId),
      omitEmptyAzureCertificate: Boolean(connectionId),
      omitEmptyKubeconfig: Boolean(connectionId),
    });
    if (connectionId) {
      await updateConnection(connectionId, payload);
      return connectionId;
    }
    const created = await createConnection(payload);
    setDraftId(created.id);
    return created.id;
  };

  const testMut = useMutation({
    mutationFn: async () => {
      const id = await ensureConnection();
      return testConnection(id);
    },
    onSuccess: (res) => {
      setTestResult(res);
      setTested(true);
      qc.invalidateQueries({ queryKey: ["config", "connections"] });
    },
    onError: (e: Error) => {
      setTestResult({ ok: false, error: e.message });
      setTested(true);
    },
  });

  const saveMut = useMutation({
    mutationFn: async () => {
      await ensureConnection();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["config", "connections"] });
      onClose();
    },
    onError: (e: Error) => setSaveError(e.message),
  });

  const currentIdx = stepIndex(step);
  const isLast = currentIdx === WIZARD_STEPS.length - 1;
  const canAdvance = canAdvanceFrom(step, data, connectionId);
  const saveEnabled = wizardComplete(data, connectionId);

  const goNext = () => {
    if (currentIdx < WIZARD_STEPS.length - 1) setStep(WIZARD_STEPS[currentIdx + 1].id);
  };
  const goBack = () => {
    if (currentIdx > 0) setStep(WIZARD_STEPS[currentIdx - 1].id);
  };

  // Enter within a text field advances the flow (or saves on the last step).
  const onContentKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "Enter" || !(e.target instanceof HTMLInputElement)) return;
    e.preventDefault();
    if (isLast) {
      if (saveEnabled && !saveMut.isPending) saveMut.mutate();
    } else if (canAdvance) {
      goNext();
    }
  };

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[300] flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="Close"
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={editing ? "Edit cloud connection" : "Add cloud connection"}
        className="provider-wizard relative flex max-h-[min(760px,calc(100vh-2rem))] w-full max-w-4xl overflow-hidden rounded-xl border border-border bg-raised shadow-pop"
      >
        {/* Left rail: stepper + live summary */}
        <aside
          ref={stepperRef}
          className="hidden w-[264px] shrink-0 flex-col border-r border-border bg-surface sm:flex"
        >
          <div className="border-b border-border px-4 py-4">
            <p className="text-sm font-semibold text-fg">
              {editing ? "Edit connection" : "Add cloud connection"}
            </p>
            <p className="mt-0.5 text-2xs text-fg-subtle">
              Step {currentIdx + 1} of {WIZARD_STEPS.length}
            </p>
          </div>
          <nav className="flex-1 overflow-y-auto p-3">
            <ol className="space-y-0.5">
              {WIZARD_STEPS.map((s, i) => {
                const active = s.id === step;
                const done = i < currentIdx;
                return (
                  <li
                    key={s.id}
                    className={cn(
                      "wizard-step-item flex items-start gap-2.5 rounded-lg px-3 py-2.5 transition-colors duration-200",
                      active && "wizard-step-active bg-ok-green/[0.07]",
                    )}
                  >
                    <span
                      className={cn(
                        "wizard-step-indicator mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-2xs font-semibold transition-colors",
                        done
                          ? "bg-ok-green text-white"
                          : active
                            ? "bg-ok-green/15 text-ok-green ring-1 ring-ok-green/30"
                            : "bg-surface-2 text-fg-subtle",
                      )}
                    >
                      {done ? <Check className="h-3 w-3" strokeWidth={3} /> : i + 1}
                    </span>
                    <span className="min-w-0">
                      <span
                        className={cn(
                          "block text-sm font-medium transition-colors duration-200",
                          active ? "text-fg" : "text-fg-subtle",
                        )}
                      >
                        {s.label}
                      </span>
                      <span className="block text-2xs text-fg-faint">{s.description}</span>
                    </span>
                  </li>
                );
              })}
            </ol>
          </nav>
        </aside>

        {/* Right: header, active step, footer */}
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex items-center justify-between border-b border-border px-5 py-3 sm:px-6">
            <p className="text-sm font-medium text-fg sm:hidden">
              {WIZARD_STEPS[currentIdx]?.label}
              <span className="ml-1.5 text-2xs text-fg-faint">
                {currentIdx + 1}/{WIZARD_STEPS.length}
              </span>
            </p>
            <button
              type="button"
              onClick={onClose}
              className="ml-auto rounded-md p-1.5 text-fg-subtle transition-colors hover:bg-surface-2 hover:text-fg"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div
            ref={contentRef}
            tabIndex={-1}
            onKeyDown={onContentKeyDown}
            className="flex-1 overflow-y-auto px-5 py-5 focus:outline-none sm:px-6"
          >
            {step === "link" && (
              <ProviderStepLink
                platform={data.platform}
                onSelect={(p: ProviderPlatform) =>
                  patchData({ platform: p, auth_method: defaultAuthMethodForPlatform(p) })
                }
              />
            )}
            {step === "details" && <ProviderStepDetails data={data} onChange={patchData} />}
            {step === "auth_method" && (
              <ProviderStepAuthMethod data={data} onChange={patchData} />
            )}
            {step === "auth" && (
              <ProviderStepAuth data={data} onChange={patchData} editing={Boolean(editing)} />
            )}
            {step === "validate" && (
              <ProviderStepValidate
                data={data}
                testResult={testResult}
                testing={testMut.isPending}
                tested={tested}
                onTest={() => testMut.mutate()}
              />
            )}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-border px-5 py-4 sm:px-6">
            <p className="min-w-0 truncate text-xs text-bad-red">{saveError}</p>
            <div className="flex shrink-0 gap-2">
              {currentIdx > 0 && (
                <Button variant="secondary" onClick={goBack}>
                  Back
                </Button>
              )}
              {!isLast ? (
                <Button variant="primary" disabled={!canAdvance} onClick={goNext}>
                  Continue
                </Button>
              ) : (
                <Button
                  variant="primary"
                  loading={saveMut.isPending}
                  disabled={!saveEnabled || saveMut.isPending}
                  onClick={() => saveMut.mutate()}
                >
                  {testResult?.ok ? "Save connection" : "Save anyway"}
                </Button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}
