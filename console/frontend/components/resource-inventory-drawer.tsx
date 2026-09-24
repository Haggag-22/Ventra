"use client";

import {
  highlightJsonSegments,
  type JsonHighlightKind,
} from "@/lib/cloudtrail-json";
import type { ResourceRow } from "@/lib/resource-inventory-detail";
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
    <pre className="ct-json">
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

export function ResourceInventoryDrawer({
  title,
  row,
  detail,
  loading,
  onClose,
}: {
  title: string;
  row: ResourceRow | null;
  detail: unknown | null;
  loading?: boolean;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!row) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [row, onClose]);

  if (!row) return null;

  return (
    <>
      <div className="ct-drawer-backdrop open" onClick={onClose} aria-hidden />
      <aside className="ct-drawer open" role="dialog" aria-label={title}>
        <div className="ct-drawer-head">
          <div className="ct-drawer-title">{title}</div>
          <button
            type="button"
            className="ct-icon-btn"
            onClick={onClose}
            title="Close"
            aria-label="Close"
          >
            <X className="h-3.5 w-3.5" strokeWidth={2} />
          </button>
        </div>
        <div className="ct-drawer-body">
          {loading && !detail ? (
            <p className="mb-3 text-xs text-fg-subtle">Loading full object…</p>
          ) : null}
          <JsonBlock value={detail ?? row} />
        </div>
      </aside>
    </>
  );
}
