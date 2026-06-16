"use client";

import {
  highlightJsonSegments,
  type JsonHighlightKind,
} from "@/lib/cloudtrail-json";
import {
  dnsQueryFailed,
  dnsQueryType,
  dnsRcode,
  dnsRcodeTone,
  looksSuspiciousDomain,
} from "@/lib/dns-query-columns";
import { fmtTime } from "@/lib/format";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AlertTriangle, X } from "lucide-react";
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

export function DnsQueryDrawer({
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

  const domain = event.resource_id || "";
  const rcode = dnsRcode(event);
  const qtype = dnsQueryType(event);
  const failed = dnsQueryFailed(event);
  const suspicious = looksSuspiciousDomain(domain);

  return (
    <>
      <div className="ct-drawer-backdrop open" onClick={onClose} aria-hidden />
      <aside className="ct-drawer open" role="dialog" aria-label="DNS query">
        <div className="ct-drawer-head">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-md border border-info/35 bg-info/10 px-2 py-0.5 text-2xs font-semibold uppercase text-info">
                Route53 Resolver
              </span>
              <span className="mono rounded-md border border-border bg-surface-2 px-2 py-0.5 text-2xs font-semibold text-fg">
                {qtype}
              </span>
              {rcode && (
                <span className={cn("mono text-xs font-semibold", dnsRcodeTone(rcode))}>{rcode}</span>
              )}
              {failed && (
                <span className="rounded-md border border-bad-red/35 bg-bad-red/10 px-2 py-0.5 text-2xs font-semibold text-bad-red">
                  Failed
                </span>
              )}
              {suspicious && (
                <span className="inline-flex items-center gap-1 rounded-md border border-high/30 bg-high/10 px-2 py-0.5 text-2xs font-semibold text-high">
                  <AlertTriangle className="h-3 w-3" /> odd
                </span>
              )}
            </div>
            <div className="ct-drawer-title mt-1 break-all">{domain || event.message}</div>
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
        <div className="ct-drawer-body">
          <div className="mb-1.5 text-2xs uppercase tracking-wide text-fg-subtle">Raw log (JSON)</div>
          <JsonBlock value={event.raw ?? {}} />
        </div>
      </aside>
    </>
  );
}
