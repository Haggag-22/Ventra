"use client";

import { AccessLogFields, WrappedLogLine } from "@/components/access-log-fields";
import {
  highlightJsonSegments,
  type JsonHighlightKind,
} from "@/lib/cloudtrail-json";
import { fmtTime } from "@/lib/format";
import {
  vpcFlowAction,
  vpcFlowActionTone,
  vpcFlowProtocol,
} from "@/lib/vpc-flow-columns";
import { vpcFlowFields } from "@/lib/vpc-flow-format";
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

export function VpcFlowDrawer({
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

  const action = vpcFlowAction(event);
  const raw = (event.raw ?? {}) as Record<string, unknown>;
  const parsedFields = vpcFlowFields(raw);
  const rawLine = String(raw.message ?? "");

  return (
    <>
      <div className="ct-drawer-backdrop open" onClick={onClose} aria-hidden />
      <aside className="ct-drawer open" role="dialog" aria-label="VPC flow log">
        <div className="ct-drawer-head">
          <div className="min-w-0 flex-1">
            <p className="text-2xs font-semibold uppercase tracking-wide text-fg-subtle">VPC Flow Log</p>
            <p className="mt-1 truncate text-sm font-semibold text-fg">{event.message || "Flow record"}</p>
            <p className="mt-0.5 mono text-xs text-fg-subtle">{fmtTime(event.timestamp)}</p>
          </div>
          <button type="button" onClick={onClose} className="ct-drawer-close" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="ct-drawer-body space-y-5">
          <dl className="ct-drawer-meta">
            <div>
              <dt>Action</dt>
              <dd className={cn("font-semibold uppercase", vpcFlowActionTone(action))}>{action}</dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>{vpcFlowProtocol(event)}</dd>
            </div>
            <div>
              <dt>Region</dt>
              <dd>{event.cloud_region || "—"}</dd>
            </div>
          </dl>

          {parsedFields.length > 0 ? (
            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                Parsed fields
              </h3>
              <AccessLogFields fields={parsedFields} />
            </section>
          ) : rawLine ? (
            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                Raw line
              </h3>
              <WrappedLogLine line={rawLine} />
            </section>
          ) : null}

          <section>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              Raw JSON
            </h3>
            <JsonBlock value={raw} />
          </section>
        </div>
      </aside>
    </>
  );
}
