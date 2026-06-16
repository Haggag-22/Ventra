"use client";

import { useCase } from "@/components/case-context";
import { FindingsTable } from "@/components/findings-table";
import { FindingsToolbar, type FindingsFilters } from "@/components/findings-toolbar";
import { PanelHeader } from "@/components/panel";
import { Button, Input, Spinner } from "@/components/ui";
import { api, type EventParams } from "@/lib/api";
import {
  ALL_FINDING_COL_KEYS,
  FINDING_VISIBLE_COLS_KEY,
  loadVisibleFindingCols,
  type FindingColKey,
} from "@/lib/findings-columns";
import { fmtNum } from "@/lib/format";
import { usePagination } from "@/lib/pagination";
import { TablePager } from "@/components/table-pager";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Bookmark, Search, ShieldAlert, Star } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const FINDING_SOURCES = ["guardduty", "securityhub", "inspector2", "macie", "detective"];

function filtersFromParams(params: EventParams): FindingsFilters {
  return {
    severity: params.severity,
    source: params.source,
    findingClass: params.finding_class,
  };
}

function paramsFromFilters(
  filters: FindingsFilters,
  q?: string,
): EventParams {
  return {
    q,
    kind: "finding",
    source: filters.source?.length ? filters.source : FINDING_SOURCES,
    severity: filters.severity,
    finding_class: filters.findingClass,
    sort: "timestamp",
    order: "desc",
  };
}

export default function SearchPage() {
  const { caseId } = useCase();
  const { params, write, clearAll } = useFilters();
  const [text, setText] = useState(params.q ?? "");
  const [saved, setSaved] = useState<string[]>([]);
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.findings.page-size");
  const [visibleColumns, setVisibleColumns] = useState<FindingColKey[]>(ALL_FINDING_COL_KEYS);

  useEffect(() => {
    setVisibleColumns(loadVisibleFindingCols());
  }, []);

  const handleColumnsChange = useCallback((cols: FindingColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(FINDING_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const filters = useMemo(() => filtersFromParams(params), [params]);
  const effective = useMemo(
    () => paramsFromFilters(filters, params.q),
    [filters, params.q],
  );

  useEffect(() => setText(params.q ?? ""), [params.q]);
  useEffect(() => {
    try {
      setSaved(JSON.parse(localStorage.getItem(`ventra.saved.${caseId}`) || "[]"));
    } catch {
      setSaved([]);
    }
  }, [caseId]);

  const run = (qv: string) => {
    write({ q: qv || undefined });
    setPage(0);
  };
  const save = () => {
    if (!text.trim()) return;
    const next = Array.from(new Set([text, ...saved])).slice(0, 12);
    setSaved(next);
    localStorage.setItem(`ventra.saved.${caseId}`, JSON.stringify(next));
  };

  const totalQ = useQuery({
    queryKey: ["findings-total", caseId],
    queryFn: () =>
      api.events(caseId, { kind: "finding", source: FINDING_SOURCES, limit: 1, offset: 0 }),
  });

  const eventsQ = useQuery({
    queryKey: ["findings", caseId, effective, page, pageSize],
    queryFn: () => api.events(caseId, { ...effective, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["findings-facets", caseId],
    queryFn: () => api.facets(caseId, { kind: "finding", source: FINDING_SOURCES }),
  });

  const total = totalQ.data?.total ?? 0;
  const matched = eventsQ.data?.total ?? 0;

  const handleChange = useCallback(
    (next: Partial<FindingsFilters>) => {
      const merged = { ...filters, ...next };
      write({
        q: params.q,
        kind: "finding",
        source: merged.source?.length ? merged.source : undefined,
        severity: merged.severity,
        finding_class: merged.findingClass,
      });
      setPage(0);
    },
    [filters, params.q, write],
  );

  const handleReset = useCallback(() => {
    setText("");
    setPage(0);
    clearAll();
  }, [clearAll]);

  return (
    <div className="flex h-full flex-col">
      <PanelHeader
        icon={ShieldAlert}
        title="Security Findings"
        panel="findings"
        actions={
          <span className="text-xs text-fg-subtle">
            {eventsQ.isFetching ? <Spinner /> : `${fmtNum(matched)} findings`}
          </span>
        }
      />

      <div className="space-y-3 border-b border-border bg-surface px-6 py-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" />
            <Input
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run(text)}
              placeholder="Search findings"
              className="pl-9"
              autoFocus
            />
          </div>
          <Button variant="primary" icon={Search} onClick={() => run(text)}>
            Search
          </Button>
          <Button variant="secondary" icon={Bookmark} onClick={save}>
            Save
          </Button>
        </div>

        <div className="cloudtrail-view">
          <FindingsToolbar
            facets={facetsQ.data}
            filters={filters}
            total={total}
            matched={matched}
            visibleColumns={visibleColumns}
            onChange={handleChange}
            onColumnsChange={handleColumnsChange}
            onReset={handleReset}
          />
        </div>

        {saved.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Star className="h-3.5 w-3.5 text-fg-subtle" />
            {saved.map((sv) => (
              <button
                key={sv}
                onClick={() => {
                  setText(sv);
                  run(sv);
                }}
                className="chip border-accent/20 hover:text-accent"
              >
                {sv}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="cloudtrail-view min-h-0 flex-1 overflow-y-auto p-6">
        <div className="ct-panel">
          <FindingsTable
            events={eventsQ.data?.events ?? []}
            loading={eventsQ.isLoading}
            visibleColumns={visibleColumns}
            emptyHint={
              params.q
                ? `No findings match “${params.q}”.`
                : "No threat or compliance findings in this case — check Logs Coverage for source gaps."
            }
          />
          <TablePager
            page={page}
            pageSize={pageSize}
            total={matched}
            shown={eventsQ.data?.events.length ?? 0}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
          />
        </div>
      </div>
    </div>
  );
}
