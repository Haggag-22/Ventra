"use client";

import { highlightJsonSegments, type JsonHighlightKind } from "@/lib/cloudtrail-json";
import type { UnifiedEvent } from "@/lib/types";
import { usePins } from "@/lib/usePins";
import { Pin, PinOff, X } from "lucide-react";
import { useEffect } from "react";
import { useCase } from "./case-context";
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

export function ContextDrawer({
  event,
  onClose,
}: {
  event: UnifiedEvent | null;
  onClose: () => void;
}) {
  const { caseId } = useCase();
  const { add, remove, has } = usePins(caseId);

  useEffect(() => {
    if (!event) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [event, onClose]);

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

  const title = event.event_action || event.message || "Event";

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30 animate-fade-in" onClick={onClose} />
      <aside
        className="fixed right-0 top-0 z-50 flex h-screen w-[680px] max-w-[95vw] flex-col border-l border-border bg-surface shadow-pop animate-slide-in"
        role="dialog"
        aria-label={title}
      >
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <h3 className="min-w-0 text-sm font-semibold text-fg break-words">{title}</h3>
          <div className="flex shrink-0 items-center gap-1">
            <Button
              size="sm"
              variant={pinned ? "primary" : "secondary"}
              icon={pinned ? PinOff : Pin}
              onClick={togglePin}
            >
              {pinned ? "Unpin" : "Pin"}
            </Button>
            <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-3">
          <JsonBlock value={event.raw ?? event} />
        </div>
      </aside>
    </>
  );
}
