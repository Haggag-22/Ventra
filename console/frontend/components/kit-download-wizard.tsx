"use client";

import { ProviderSelector } from "@/components/provider-selector";
import { Button } from "@/components/ui";
import { WizardLayout } from "@/components/wizard-layout";
import type { CollectionProfile } from "@/lib/api";
import { ACQUIRE_PLATFORM_LABELS, isAcquirePlatform } from "@/lib/catalog";
import { readLastConnection, writeLastConnection } from "@/lib/provider-storage";
import { useEffect, useState } from "react";

type Props = {
  open: boolean;
  kit: CollectionProfile | null;
  onClose: () => void;
  onConfirm: (payload: { connectionId: string }) => void;
  downloading?: boolean;
  error?: string;
};

const STEPS = [{ id: "auth" as const, label: "Authentication", description: "Embed credentials" }];

function platformLabel(cloud: string): string {
  const key = cloud.toLowerCase() as keyof typeof ACQUIRE_PLATFORM_LABELS;
  return ACQUIRE_PLATFORM_LABELS[key] ?? cloud.toUpperCase();
}

export function KitDownloadWizard({ open, kit, onClose, onConfirm, downloading, error }: Props) {
  const [connectionId, setConnectionId] = useState("");
  const [localError, setLocalError] = useState("");

  const cloud = (kit?.cloud || "aws").toLowerCase();
  const providerLabel = platformLabel(cloud);

  useEffect(() => {
    if (!open) return;
    setLocalError("");
    const saved = readLastConnection();
    if (saved) setConnectionId(saved);
  }, [open, kit?.id]);

  const validate = (): string | null => {
    if (!connectionId.trim()) {
      return `Choose a ${providerLabel} connection to embed in the kit.`;
    }
    return null;
  };

  const download = () => {
    setLocalError("");
    const err = validate();
    if (err) {
      setLocalError(err);
      return;
    }
    writeLastConnection(connectionId);
    onConfirm({ connectionId: connectionId.trim() });
  };

  const shownError = localError || error;

  return (
    <WizardLayout
      open={open}
      onClose={onClose}
      closeDisabled={downloading}
      steps={STEPS}
      currentStepId="auth"
      ariaLabel={`Download collection kit: ${kit?.name ?? ""}`}
      footer={
        <div className="flex items-center justify-between gap-3 px-5 py-4 sm:px-6">
          <p className="min-w-0 truncate text-xs text-bad-red">{shownError}</p>
          <Button variant="primary" loading={downloading} disabled={downloading} onClick={download}>
            Download Kit
          </Button>
        </div>
      }
    >
      <div className="space-y-3">
        <p className="text-sm text-fg-subtle">
          Choose the {providerLabel} connection to embed in the zip. The client operator can then run{" "}
          <span className="mono text-fg">python3 ventra.py --out ./evidence</span> without extra auth flags.
        </p>
        <ProviderSelector
          platform={isAcquirePlatform(cloud) || cloud === "m365" ? cloud : "aws"}
          value={connectionId}
          onChange={setConnectionId}
          elevated
        />
      </div>
    </WizardLayout>
  );
}
