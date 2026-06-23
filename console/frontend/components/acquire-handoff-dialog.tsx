"use client";

import { Button } from "@/components/ui";
import type { KitHandoffRecord } from "@/lib/acquire-handoff";
import { deploymentProfileLabel, isEnterpriseProfile } from "@/lib/deployment-profiles";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import {
  HANDOFF_MODES,
  handoffModeLabel,
  parseHandoffMode,
} from "@/lib/handoff-modes";
import { CheckCircle2, ClipboardList, CloudDownload, Upload, X } from "lucide-react";

const STANDARD_STEPS = [
  "Send the kit zip to the client operator (secure channel).",
  "Client attaches the narrowed IAM policy from iam/ and runs the kit in their environment.",
  "Client returns the sealed evidence package (.tar.zst) to your IR team.",
  "Import the package into Ventra Investigate to continue analysis.",
];

const ENTERPRISE_FILE_STEPS = [
  "Send the kit zip to the client operator (secure channel).",
  "Client runs collection on EC2/VM using the Enterprise profile (no record cap).",
  "Client returns the sealed package (.tar.zst) to your IR team.",
  "Use Import package on Cases when the file arrives.",
];

const ENTERPRISE_IR_BUCKET_STEPS = [
  "Send the kit zip to the client operator (secure channel).",
  "Client runs collection on EC2/VM using the Enterprise profile (no record cap).",
  "Kit uploads the sealed package to your IR S3 bucket automatically.",
  "Use Import from S3 on Cases when collection completes (Ventra reads your bucket server-side).",
];

const ENTERPRISE_PRESIGNED_STEPS = [
  "Send the kit zip to the client operator (secure channel).",
  "Client runs collection on EC2/VM using the Enterprise profile (no record cap).",
  "Kit uploads via the presigned PUT URL you configured — client needs no bucket IAM.",
  "Ingest from your bucket after upload (Import from S3 or Import package).",
];

function stepsForHandoff(handoff: KitHandoffRecord): string[] {
  if (!isEnterpriseProfile(handoff.deploymentProfile)) return STANDARD_STEPS;
  const mode = parseHandoffMode(handoff.handoffMode);
  if (mode === "s3_ir_bucket") return ENTERPRISE_IR_BUCKET_STEPS;
  if (mode === "presigned") return ENTERPRISE_PRESIGNED_STEPS;
  return ENTERPRISE_FILE_STEPS;
}

type Props = {
  open: boolean;
  handoff: KitHandoffRecord | null;
  onClose: () => void;
  onImport: () => void;
  onImportS3?: () => void;
};

export function AcquireHandoffDialog({ open, handoff, onClose, onImport, onImportS3 }: Props) {
  if (!open || !handoff) return null;

  const enterprise = isEnterpriseProfile(handoff.deploymentProfile);
  const handoffMode = parseHandoffMode(handoff.handoffMode);
  const modeInfo = HANDOFF_MODES.find((m) => m.id === handoffMode);
  const steps = stepsForHandoff(handoff);
  const showS3Import =
    enterprise && handoffMode !== "file" && !!handoff.transport && !!onImportS3;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4 animate-fade-in"
      onMouseDown={onClose}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <CheckCircle2 className="h-4 w-4 text-ok-green" /> Kit downloaded — operator handoff
          </h3>
          <button type="button" onClick={onClose} className="text-fg-subtle hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <p className="text-sm text-fg-subtle">
            Case <span className="mono font-medium text-fg">{handoff.caseId}</span> ·{" "}
            {deploymentProfileLabel(handoff.deploymentProfile)} profile ·{" "}
            {handoff.collectors.length} artifact{handoff.collectors.length === 1 ? "" : "s"}
            {enterprise && (
              <>
                {" "}
                · {handoffModeLabel(handoffMode)}
              </>
            )}
          </p>

          {enterprise && modeInfo && (
            <div className="rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-xs">
              <p className="font-medium text-fg">{modeInfo.label}</p>
              <p className="mt-1 text-fg-subtle">{modeInfo.analystNote}</p>
              {handoff.transport && (
                <p className="mono mt-2 break-all text-2xs text-fg-subtle">{handoff.transport}</p>
              )}
            </div>
          )}

          <div>
            <div className="mb-2 flex items-center gap-2 text-xs font-medium text-fg-subtle">
              <ClipboardList className="h-3.5 w-3.5" /> Post-download checklist
            </div>
            <ol className="space-y-2 text-sm text-fg">
              {steps.map((step, i) => (
                <li key={i} className="flex gap-2">
                  <span className="mono text-2xs text-fg-subtle">{i + 1}.</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>

          <div className="rounded-lg border border-border bg-surface-2 px-3 py-2">
            <p className="text-2xs font-medium uppercase tracking-wide text-fg-subtle">
              Expected artifacts
            </p>
            <ul className="mt-1.5 max-h-24 space-y-0.5 overflow-auto text-xs text-fg">
              {handoff.collectors.map((c) => (
                <li key={c} className="mono">
                  {displayArtifactLabel(c)}
                </li>
              ))}
            </ul>
          </div>

          <div className="flex flex-wrap justify-end gap-2 pt-1">
            <Button variant="secondary" onClick={onClose}>
              Done
            </Button>
            {showS3Import && (
              <Button variant="primary-dark" icon={CloudDownload} onClick={onImportS3}>
                Import from S3
              </Button>
            )}
            {(!enterprise || handoffMode === "file") && (
              <Button variant="primary-dark" icon={Upload} onClick={onImport}>
                Import evidence
              </Button>
            )}
          </div>
          <p className="text-2xs text-fg-subtle">
            {enterprise && handoffMode === "s3_ir_bucket"
              ? "Import from S3 uses credentials on your Ventra server — not the client's browser."
              : enterprise && handoffMode === "presigned"
                ? "After the client uploads via presigned URL, ingest from your bucket."
                : "Opens the import dialog on Cases with case ID pre-filled."}
          </p>
        </div>
      </div>
    </div>
  );
}
