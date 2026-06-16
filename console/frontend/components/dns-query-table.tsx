"use client";

import { DnsQueryDrawer } from "@/components/dns-query-drawer";
import { Entity } from "@/components/pivot";
import { Spinner } from "@/components/ui";
import {
  DEFAULT_DNS_QUERY_WIDTHS,
  DNS_QUERY_COLS,
  DNS_QUERY_WIDTHS_KEY,
  dnsInstanceId,
  dnsQueryFailed,
  dnsQueryType,
  dnsRcode,
  dnsRcodeTone,
  dnsVpcId,
  loadDnsQueryWidths,
  looksSuspiciousDomain,
  type DnsQueryColKey,
} from "@/lib/dns-query-columns";
import { fmtTimeCloudTrail } from "@/lib/format";
import type { UnifiedEvent } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AlertTriangle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

export function DnsQueryTable({
  events,
  loading,
}: {
  events: UnifiedEvent[];
  loading?: boolean;
}) {
  const [selected, setSelected] = useState<UnifiedEvent | null>(null);
  const [widths, setWidths] = useState(DEFAULT_DNS_QUERY_WIDTHS);
  const resizing = useRef<{ key: DnsQueryColKey; startX: number; startW: number } | null>(null);

  useEffect(() => {
    setWidths(loadDnsQueryWidths());
  }, []);

  const persistWidths = useCallback((next: Record<DnsQueryColKey, number>) => {
    try {
      localStorage.setItem(DNS_QUERY_WIDTHS_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const startResize = useCallback(
    (key: DnsQueryColKey, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = DNS_QUERY_COLS.find((c) => c.key === key);
      const min = col?.min ?? 60;
      resizing.current = {
        key,
        startX: e.clientX,
        startW: widths[key] ?? DEFAULT_DNS_QUERY_WIDTHS[key],
      };

      const onMove = (ev: MouseEvent) => {
        if (!resizing.current) return;
        const delta = ev.clientX - resizing.current.startX;
        const w = Math.max(min, resizing.current.startW + delta);
        setWidths((prev) => ({ ...prev, [key]: w }));
      };

      const onUp = () => {
        resizing.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        setWidths((prev) => {
          persistWidths(prev);
          return prev;
        });
      };

      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    },
    [widths, persistWidths],
  );

  const totalWeight = DNS_QUERY_COLS.reduce(
    (sum, c) => sum + (widths[c.key] ?? DEFAULT_DNS_QUERY_WIDTHS[c.key]),
    0,
  );

  const colWidth = (key: DnsQueryColKey) =>
    `${widths[key] ?? DEFAULT_DNS_QUERY_WIDTHS[key]}px`;

  const renderCell = (key: DnsQueryColKey, e: UnifiedEvent) => {
    const domain = e.resource_id || "";
    const rcode = dnsRcode(e);
    const suspicious = looksSuspiciousDomain(domain);

    switch (key) {
      case "timestamp":
        return (
          <td key={key} className="mono truncate text-fg-subtle">
            {fmtTimeCloudTrail(e.timestamp)}
          </td>
        );
      case "domain":
        return (
          <td key={key} className="align-top">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="break-all text-fg" title={domain}>
                {domain || "—"}
              </span>
              {suspicious && (
                <span
                  className="chip shrink-0 border-high/30 bg-high/10 text-high"
                  title="Long labels / deep subdomains / high digit density"
                >
                  <AlertTriangle className="h-3 w-3" /> odd
                </span>
              )}
            </div>
          </td>
        );
      case "qtype":
        return (
          <td key={key} className="mono truncate font-medium text-fg">
            {dnsQueryType(e)}
          </td>
        );
      case "rcode":
        return (
          <td key={key} className="mono truncate">
            {rcode ? (
              <span className={cn("font-semibold", dnsRcodeTone(rcode))}>{rcode}</span>
            ) : (
              "—"
            )}
          </td>
        );
      case "answer":
        return (
          <td key={key} className="truncate" onClick={(ev) => ev.stopPropagation()}>
            {e.dest_ip ? <Entity kind="ip" value={e.dest_ip} /> : "—"}
          </td>
        );
      case "client":
        return (
          <td key={key} className="truncate" onClick={(ev) => ev.stopPropagation()}>
            {e.source_ip ? <Entity kind="ip" value={e.source_ip} /> : "—"}
          </td>
        );
      case "instance":
        return (
          <td key={key} className="mono truncate text-fg-subtle" title={dnsInstanceId(e) || undefined}>
            {dnsInstanceId(e) || "—"}
          </td>
        );
      case "vpc":
        return (
          <td key={key} className="mono truncate text-fg-subtle" title={dnsVpcId(e) || undefined}>
            {dnsVpcId(e) || "—"}
          </td>
        );
      default:
        return null;
    }
  };

  return (
    <div className="relative">
      {loading && events.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Spinner />
        </div>
      ) : (
        <>
          <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
            <table
              className="ct-table w-full border-collapse text-left"
              style={{ tableLayout: "fixed", width: totalWeight, minWidth: "100%" }}
            >
              <colgroup>
                {DNS_QUERY_COLS.map((c) => (
                  <col key={c.key} style={{ width: colWidth(c.key) }} />
                ))}
              </colgroup>
              <thead className="sticky top-0 z-10">
                <tr>
                  {DNS_QUERY_COLS.map((c) => (
                    <th key={c.key} className="relative">
                      <span className="block truncate pr-2">{c.label}</span>
                      <span
                        role="separator"
                        aria-orientation="vertical"
                        aria-label={`Resize ${c.label} column`}
                        onMouseDown={(e) => startResize(c.key, e)}
                        onClick={(e) => e.stopPropagation()}
                        className="ct-col-resize"
                      />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => {
                  const failed = dnsQueryFailed(e);
                  return (
                    <tr
                      key={`${e.timestamp}-${e.resource_id}-${i}`}
                      onClick={() => setSelected(e)}
                      className={failed ? "bg-bad-red/[0.03]" : undefined}
                    >
                      {DNS_QUERY_COLS.map((c) => renderCell(c.key, e))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {!loading && events.length === 0 && (
            <div className="px-4 py-16 text-center text-sm text-fg-subtle">
              No DNS queries match the current filters.
            </div>
          )}
        </>
      )}

      <DnsQueryDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
