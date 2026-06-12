"use client";

import { highlightJsonSegments, type JsonHighlightKind } from "@/lib/cloudtrail-json";
import type { IamPolicyEntry } from "@/lib/iam-policies";
import { policyKindLabel } from "@/lib/iam-policies";
import { ChevronLeft, ChevronRight, FileKey2, X } from "lucide-react";
import { useEffect, useState } from "react";

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
  const [selected, setSelected] = useState<number | null>(null);
  const active = selected !== null ? policies[selected] : null;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (selected !== null) setSelected(null);
        else onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, selected]);

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
            {selected !== null && (
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="mb-2 inline-flex items-center gap-1 text-2xs text-accent hover:underline"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                All policies
              </button>
            )}
            <div className="text-2xs uppercase tracking-wide text-fg-subtle">
              {principalType === "user" ? "IAM user" : "IAM role"}
            </div>
            <h3 className="mt-1 text-sm font-semibold text-fg break-words">{principal}</h3>
            <p className="mt-1 text-2xs text-fg-subtle">
              {policies.length === 0
                ? "No policies in snapshot"
                : active
                  ? policyKindLabel(active.kind)
                  : `${policies.length} polic${policies.length === 1 ? "y" : "ies"} — click to view`}
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

        <div className="flex-1 overflow-y-auto px-4 py-3">
          {policies.length === 0 ? (
            <p className="text-sm text-fg-subtle">
              No IAM policies were attached to this {principalType} in the collected snapshot.
            </p>
          ) : active ? (
            <section className="space-y-3">
              <div>
                <div className="text-sm font-medium text-fg">{active.name}</div>
                {active.arn && (
                  <div className="mono mt-1 text-2xs text-fg-subtle break-all">{active.arn}</div>
                )}
                {active.viaGroup && (
                  <div className="mt-1 text-2xs text-fg-subtle">Inherited via group {active.viaGroup}</div>
                )}
              </div>
              <JsonBlock value={active.document} />
            </section>
          ) : (
            <ul className="space-y-1">
              {policies.map((p, i) => (
                <li key={`${p.kind}-${p.name}-${i}`}>
                  <button
                    type="button"
                    onClick={() => setSelected(i)}
                    className="flex w-full items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5 text-left transition-colors hover:border-accent/40 hover:bg-accent/5"
                  >
                    <FileKey2 className="h-4 w-4 shrink-0 text-fg-subtle" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium text-fg">{p.name}</div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                        <span className="chip">{policyKindLabel(p.kind)}</span>
                        {p.viaGroup && <span className="chip">via {p.viaGroup}</span>}
                      </div>
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-fg-subtle" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </aside>
    </>
  );
}
