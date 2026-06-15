"use client";

import { highlightJsonSegments, type JsonHighlightKind } from "@/lib/cloudtrail-json";
import { CATEGORY_COLORS } from "@/lib/severity";
import { fmtBytes, fmtTime } from "@/lib/format";
import type { UnifiedEvent } from "@/lib/types";
import { usePins } from "@/lib/usePins";
import { cn } from "@/lib/utils";
import { Braces, Pin, PinOff, X } from "lucide-react";
import { useState } from "react";
import { useCase } from "./case-context";
import { OutcomeBadge, SeverityBadge } from "./badges";
import { Entity } from "./pivot";
import { Button } from "./ui";

const JSON_CLASS: Record<JsonHighlightKind, string | undefined> = {
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
            <span key={i} className={JSON_CLASS[seg.kind]}>
              {seg.text}
            </span>
          ),
        )}
      </code>
    </pre>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2 py-1.5">
      <div className="text-2xs uppercase tracking-wide text-fg-subtle pt-0.5">{label}</div>
      <div className="text-sm text-fg break-words min-w-0">{children}</div>
    </div>
  );
}

export function ContextDrawer({
  event,
  onClose,
}: {
  event: UnifiedEvent | null;
  onClose: () => void;
}) {
  const { caseId } = useCase();
  const { add, remove, has } = usePins(caseId);
  const [showRaw, setShowRaw] = useState(false);
  if (!event) return null;

  const pinId = `event-${event.message}-${event.timestamp}`;
  const pinned = has(pinId);
  const togglePin = () =>
    pinned
      ? remove(pinId)
      : add({
          kind: event.event_kind === "finding" ? "finding" : "event",
          title: `${event.event_action || event.message}`,
          detail: event.message,
          timestamp: event.timestamp,
          ref: { action: event.event_action, ip: event.source_ip, user: event.user_name },
        });

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30 animate-fade-in" onClick={onClose} />
      <aside className="fixed right-0 top-0 z-50 flex h-screen w-[680px] max-w-[95vw] flex-col border-l border-border bg-surface shadow-pop animate-slide-in">
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={event.event_severity} />
              <OutcomeBadge outcome={event.event_outcome} />
              <span className="chip">{event.ventra_source}</span>
            </div>
            <h3 className="mt-2 text-sm font-semibold text-fg break-words">
              {event.event_action || event.message}
            </h3>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex items-center gap-2 border-b border-border px-4 py-2">
          <Button
            size="sm"
            variant={showRaw ? "primary" : "secondary"}
            icon={Braces}
            onClick={() => setShowRaw((v) => !v)}
          >
            {showRaw ? "Hide raw log" : "Show raw log"}
          </Button>
          <Button
            size="sm"
            variant={pinned ? "primary" : "secondary"}
            icon={pinned ? PinOff : Pin}
            onClick={togglePin}
          >
            {pinned ? "Pinned to report" : "Pin to report"}
          </Button>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-2">
          <Field label="Time">
            <span className="mono text-xs">{fmtTime(event.timestamp)}</span>
          </Field>
          <Field label="Message">{event.message}</Field>
          <Field label="Categories">
            <div className="flex flex-wrap gap-1">
              {event.event_category.map((c) => (
                <span
                  key={c}
                  className="rounded px-1.5 py-0.5 text-2xs"
                  style={{ background: `${CATEGORY_COLORS[c] ?? "rgb(120 120 120)"}22`, color: CATEGORY_COLORS[c] ?? "rgb(150 150 150)" }}
                >
                  {c}
                </span>
              ))}
            </div>
          </Field>
          <Field label="Service">
            <span className="mono text-xs">{event.cloud_service || "—"}</span>
          </Field>
          <Field label="Region">
            <span className="mono text-xs">{event.cloud_region || "—"}</span>
          </Field>

          <div className="my-2 h-px bg-border" />

          <Field label="Principal">
            {event.user_name ? <Entity kind="user" value={event.user_name} mono={false} /> : "—"}
          </Field>
          <Field label="User type">
            <span className="mono text-xs">{event.user_type || "—"}</span>
          </Field>
          <Field label="ARN">
            {event.user_arn ? <Entity kind="user" value={event.user_arn} /> : "—"}
          </Field>
          <Field label="Source IP">
            {event.source_ip ? (
              <span className="flex flex-wrap items-center gap-2">
                <Entity kind="ip" value={event.source_ip} />
                {event.source_country && <span className="chip">{event.source_country}</span>}
                {event.source_asn && <span className="chip">{event.source_asn}</span>}
              </span>
            ) : (
              "—"
            )}
          </Field>

          {(event.dest_ip || event.dest_bytes) && (
            <>
              <div className="my-2 h-px bg-border" />
              <Field label="Destination">
                {event.dest_ip ? <Entity kind="ip" value={event.dest_ip} /> : "—"}
                {event.dest_port ? <span className="mono text-xs">:{event.dest_port}</span> : null}
              </Field>
              <Field label="Bytes">
                <span className="mono text-xs">{fmtBytes(event.dest_bytes)}</span>
              </Field>
            </>
          )}

          {event.resource_arn && (
            <>
              <div className="my-2 h-px bg-border" />
              <Field label="Resource">
                <Entity kind="resource" value={event.resource_arn} />
              </Field>
              <Field label="Type">
                <span className="mono text-xs">{event.resource_type || "—"}</span>
              </Field>
            </>
          )}

          <div className="my-3">
            <Button
              variant={showRaw ? "primary" : "secondary"}
              icon={Braces}
              onClick={() => setShowRaw((v) => !v)}
              className="w-full justify-center"
            >
              {showRaw ? "Hide raw log" : "Show raw log"}
            </Button>
            {showRaw && (
              <div className="mt-3">
                <JsonBlock value={event.raw} />
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}
