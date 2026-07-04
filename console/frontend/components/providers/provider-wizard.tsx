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
import { ProviderStepAuth } from "./provider-step-auth";
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
  wizardDataToConnection,
  type ProviderPlatform,
  type ProviderWizardData,
  type WizardStepId,
} from "./types";

function stepIndex(id: WizardStepId): number {
  return WIZARD_STEPS.findIndex((s) => s.id === id);
}

function canAdvanceFrom(step: WizardStepId, data: ProviderWizardData): boolean {
  if (step === "link") {
    return Boolean(data.platform) && data.platform !== "kubernetes";
  }
  if (step === "details") {
    if (!data.platform || data.platform === "kubernetes") return false;
    if (data.platform === "aws" && data.auth_method === "role" && !data.role_arn.trim()) {
      return false;
    }
    return true;
  }
  if (step === "auth") {
    if (data.platform === "aws" && data.auth_method === "role" && !data.role_arn.trim()) {
      return false;
    }
    return Boolean(data.platform) && data.platform !== "kubernetes";
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
          const tl = gsap.timeline({ defaults: { ease: "power2.out" } });
          tl.from(contentRef.current, {
            x: reduceMotion ? 0 : 20,
            autoAlpha: reduceMotion ? 1 : 0,
            duration: reduceMotion ? 0 : 0.25,
          });
          tl.from(
            ".wizard-step-item",
            {
              autoAlpha: reduceMotion ? 1 : 0,
              x: reduceMotion ? 0 : -8,
              duration: reduceMotion ? 0 : 0.2,
              stagger: reduceMotion ? 0 : 0.05,
            },
            reduceMotion ? 0 : "-=0.1",
          );
        },
        dialogRef,
      );
      return () => mm.revert();
    },
    { scope: dialogRef, dependencies: [step], revertOnUpdate: true },
  );

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add("(prefers-reduced-motion: no-preference)", () => {
        gsap.to(".wizard-step-indicator", {
          scale: 1,
          duration: 0.25,
          ease: "power2.out",
          stagger: 0.04,
        });
        gsap.to(".wizard-step-active .wizard-step-indicator", {
          scale: 1.08,
          duration: 0.25,
          ease: "back.out(1.4)",
        });
      }, stepperRef);
      return () => mm.revert();
    },
    { scope: stepperRef, dependencies: [step] },
  );

  const patchData = (patch: Partial<ProviderWizardData>) => {
    setData((prev) => ({ ...prev, ...patch }));
    setTestResult(null);
    setTested(false);
  };

  const ensureConnection = async (): Promise<string> => {
    const payload = wizardDataToConnection(data);
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

  const goNext = () => {
    if (currentIdx < WIZARD_STEPS.length - 1) {
      setStep(WIZARD_STEPS[currentIdx + 1].id);
    }
  };

  const goBack = () => {
    if (currentIdx > 0) {
      setStep(WIZARD_STEPS[currentIdx - 1].id);
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

  const saveEnabled = Boolean(data.platform) && data.platform !== "kubernetes";

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
        className="relative flex max-h-[min(720px,calc(100vh-2rem))] w-full max-w-4xl overflow-hidden rounded-xl border border-border bg-raised shadow-pop"
      >
        {/* Left stepper */}
        <aside
          ref={stepperRef}
          className="hidden w-56 shrink-0 flex-col border-r border-border bg-surface sm:flex"
        >
          <div className="border-b border-border px-4 py-4">
            <p className="text-sm font-semibold text-fg">
              {editing ? "Edit provider" : "Add provider"}
            </p>
          </div>
          <nav className="flex-1 space-y-0.5 p-3">
            {WIZARD_STEPS.map((s, i) => {
              const active = s.id === step;
              const done = i < currentIdx;
              return (
                <div
                  key={s.id}
                  className={cn(
                    "wizard-step-item flex items-start gap-2.5 rounded-lg px-3 py-2.5 transition-colors duration-200",
                    active && "wizard-step-active bg-accent/10",
                  )}
                >
                  <span
                    className={cn(
                      "wizard-step-indicator mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-2xs font-semibold",
                      done
                        ? "bg-accent text-accent-fg"
                        : active
                          ? "bg-accent/20 text-accent ring-1 ring-accent/40"
                          : "bg-surface-2 text-fg-subtle",
                    )}
                  >
                    {done ? <Check className="h-3 w-3" /> : i + 1}
                  </span>
                  <span>
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
                </div>
              );
            })}
          </nav>
        </aside>

        {/* Right content */}
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex items-center justify-between border-b border-border px-5 py-3 sm:px-6">
            <p className="text-sm font-medium text-fg sm:hidden">
              {WIZARD_STEPS[currentIdx]?.label}
            </p>
            <div className="ml-auto">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md p-1.5 text-fg-subtle hover:bg-surface-2 hover:text-fg"
                aria-label="Close wizard"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          <div ref={contentRef} className="flex-1 overflow-y-auto px-5 py-5 sm:px-6">
            {step === "link" && (
              <ProviderStepLink
                platform={data.platform}
                onSelect={(p: ProviderPlatform) => patchData({ platform: p })}
              />
            )}
            {step === "details" && (
              <ProviderStepDetails data={data} onChange={patchData} />
            )}
            {step === "auth" && <ProviderStepAuth data={data} onChange={patchData} />}
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
            <div>
              {saveError && <p className="text-xs text-bad-red">{saveError}</p>}
            </div>
            <div className="flex gap-2">
              {currentIdx > 0 && (
                <Button variant="secondary" onClick={goBack}>
                  Back
                </Button>
              )}
              {!isLast ? (
                <Button
                  variant="primary-dark"
                  className="bg-accent text-accent-fg hover:bg-accent/90"
                  disabled={!canAdvanceFrom(step, data)}
                  onClick={goNext}
                >
                  Next
                </Button>
              ) : (
                <Button
                  variant="primary-dark"
                  className="bg-accent text-accent-fg hover:bg-accent/90"
                  loading={saveMut.isPending}
                  disabled={!saveEnabled || saveMut.isPending}
                  onClick={() => saveMut.mutate()}
                >
                  Save provider
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
