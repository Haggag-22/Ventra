"use client";

import { Button } from "@/components/ui";
import type { KitHandoffRecord } from "@/lib/acquire-handoff";
import { deploymentProfileLabel } from "@/lib/deployment-profiles";
import { displayArtifactLabel } from "@/lib/artifact-icons";
import { CheckCircle2, ClipboardList, Upload, X } from "lucide-react";

const HANDOFF_STEPS = [
  "Send the kit zip to the client operator (secure channel).",
  "Client attaches the narrowed IAM policy from iam/ and runs the kit in their environment.",
  "Client returns the sealed evidence package (.tar.zst) to your IR team.",
  "Import the package into Ventra Investigate to continue analysis.",
];

type Props = {
  open: boolean;
  handoff: KitHandoffRecord | null;
  onClose: () => void;
  onImport: () => void;
};

export function AcquireHandoffDialog({ open, handoff, onClose, onImport }: Props) {
  if (!open || !handoff) return null;

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
          </p>

          <div>
            <div className="mb-2 flex items-center gap-2 text-xs font-medium text-fg-subtle">
              <ClipboardList className="h-3.5 w-3.5" /> Post-download checklist
            </div>
            <ol className="space-y-2 text-sm text-fg">
              {HANDOFF_STEPS.map((step, i) => (
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
            <Button variant="primary-dark" icon={Upload} onClick={onImport}>
              Import evidence
            </Button>
          </div>
          <p className="text-2xs text-fg-subtle">
            Opens the import dialog on Cases with case ID pre-filled. Use this when the client
            returns the sealed <span className="mono">.tar.zst</span> package.
          </p>
        </div>
      </div>
    </div>
  );
}
