"use client";

import { AccessLogFields, WrappedLogLine } from "@/components/access-log-fields";
import {
  EDGE_SOURCE_CHIP,
  EDGE_SOURCE_LABEL,
  edgeHttpStatus,
  edgeStatusTone,
} from "@/lib/edge-request-columns";
import { parseAccessLogLine } from "@/lib/access-log-format";
import {
  highlightJsonSegments,
  type JsonHighlightKind,
} from "@/lib/cloudtrail-json";
import { fmtTime } from "@/lib/format";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
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

export function EdgeRequestDrawer({
  event,
  onClose,
}: {
  event: UnifiedEvent | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!event) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [event, onClose]);

  if (!event) return null;

  const source = event.ventra_source;
  const sourceLabel = EDGE_SOURCE_LABEL[source] ?? source;
  const chip = EDGE_SOURCE_CHIP[source] ?? "border-border bg-surface-2 text-fg-subtle";
  const status = edgeHttpStatus(event);
  const rawLine = String(event.raw?.line ?? "");
  const parsedFields = rawLine
    ? parseAccessLogLine(rawLine, source, event.raw as Record<string, unknown> | undefined)
    : null;

  return (
    <>
      <div className="ct-drawer-backdrop open" onClick={onClose} aria-hidden />
      <aside className="ct-drawer open" role="dialog" aria-label="Edge request">
        <div className="ct-drawer-head">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className={cn("rounded-md border px-2 py-0.5 text-2xs font-semibold uppercase", chip)}>
                {sourceLabel}
              </span>
              {status && (
                <span className={cn("mono text-xs font-semibold", edgeStatusTone(status))}>
                  {status}
                </span>
              )}
            </div>
            <div className="ct-drawer-title mt-1 truncate">{event.message || event.event_action}</div>
            <div className="mono mt-0.5 text-2xs text-fg-subtle">{fmtTime(event.timestamp)}</div>
          </div>
          <button
            type="button"
            className="ct-icon-btn shrink-0"
            onClick={onClose}
            title="Close"
            aria-label="Close"
          >
            <X className="h-3.5 w-3.5" strokeWidth={2} />
          </button>
        </div>
        <div className="ct-drawer-body space-y-4">
          {rawLine && (
            <div>
              <div className="mb-1.5 text-2xs uppercase tracking-wide text-fg-subtle">Raw log line</div>
              {parsedFields ? (
                <AccessLogFields fields={parsedFields} />
              ) : (
                <WrappedLogLine line={rawLine} />
              )}
            </div>
          )}
          <div>
            <div className="mb-1.5 text-2xs uppercase tracking-wide text-fg-subtle">Collector record</div>
            <JsonBlock value={event.raw ?? {}} />
          </div>
        </div>
      </aside>
    </>
  );
}
