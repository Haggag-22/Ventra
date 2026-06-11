"use client";

import { highlightJsonSegments, type JsonHighlightKind } from "@/lib/cloudtrail-json";
import type { IamPolicyEntry } from "@/lib/iam-policies";
import { policyKindLabel } from "@/lib/iam-policies";
import { X } from "lucide-react";
import { useEffect } from "react";

const CLASS: Record<JsonHighlightKind, string | undefined> = {
  key: "j-key",
  str: "j-str",
  num: "j-num",
  bool: "j-bool",
  null: "j-null",
  plain: undefined,
};

function JsonBlock({ value }: { value: unknown }) {
  const segments = highlightJsonSegments(value);
  return (
    <pre className="rounded-md border border-border bg-surface-2 p-3 text-2xs leading-relaxed overflow-x-auto">
      <code>
        {segments.map((seg, i) =>
          seg.kind === "plain" ? (
            <span key={i}>{seg.text}</span>
          ) : (
            <span key={i} className={CLASS[seg.kind]}>
              {seg.text}
            </span>
          ),
        )}
      </code>
    </pre>
  );
}

export function IamPolicyDrawer({
  principal,
  principalType,
  policies,
  onClose,
}: {
  principal: string;
  principalType: "user" | "role";
  policies: IamPolicyEntry[];
  onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30 animate-fade-in" onClick={onClose} aria-hidden />
      <aside
        className="fixed right-0 top-0 z-50 flex h-screen w-[520px] max-w-[92vw] flex-col border-l border-border bg-surface shadow-pop animate-slide-in"
        role="dialog"
        aria-label={`Policies for ${principal}`}
      >
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <div className="text-2xs uppercase tracking-wide text-fg-subtle">
              {principalType === "user" ? "IAM user" : "IAM role"}
            </div>
            <h3 className="mt-1 text-sm font-semibold text-fg break-words">{principal}</h3>
            <p className="mt-1 text-2xs text-fg-subtle">
              {policies.length} polic{policies.length === 1 ? "y" : "ies"}
            </p>
          </div>
          <button
            type="button"
            className="rounded-md p-1.5 text-fg-subtle hover:bg-surface-2 hover:text-fg"
            onClick={onClose}
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
          {policies.map((p, i) => (
            <section key={`${p.kind}-${p.name}-${i}`}>
              <div className="mb-1.5 flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-fg">{p.name}</span>
                <span className="chip">{policyKindLabel(p.kind)}</span>
                {p.viaGroup && <span className="chip">via {p.viaGroup}</span>}
              </div>
              {p.arn && <div className="mono mb-2 text-2xs text-fg-subtle break-all">{p.arn}</div>}
              <JsonBlock value={p.document} />
            </section>
          ))}
        </div>
      </aside>
    </>
  );
}
