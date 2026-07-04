"use client";

import { useCase } from "@/components/case-context";
import { FindingsTable } from "@/components/findings-table";
import { FindingsToolbar, type FindingsFilters } from "@/components/findings-toolbar";
import { PanelBody, PanelHeader } from "@/components/panel";
import { api, type EventParams } from "@/lib/api";
import {
  ALL_FINDING_COL_KEYS,
  FINDING_VISIBLE_COLS_KEY,
  loadVisibleFindingCols,
  type FindingColKey,
} from "@/lib/findings-columns";
import { usePagination } from "@/lib/pagination";
import { caseCloud, findingSources } from "@/lib/cloud-sources";
import { panelLabel } from "@/lib/panel-labels";
import { TablePager } from "@/components/table-pager";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ShieldAlert, Star } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

function defaultFindingSources(cloud: ReturnType<typeof caseCloud>) {
  return findingSources(cloud);
}

function filtersFromParams(params: EventParams): FindingsFilters {
  return {
    severity: params.severity,
    source: params.source,
    findingClass: params.finding_class,
  };
}

function paramsFromFilters(
  filters: FindingsFilters,
  cloud: ReturnType<typeof caseCloud>,
  q?: string,
): EventParams {
  const sources = defaultFindingSources(cloud);
  return {
    q,
    kind: "finding",
    source: filters.source?.length ? filters.source : sources,
    severity: filters.severity,
    finding_class: filters.findingClass,
    sort: "timestamp",
    order: "desc",
  };
}

export default function SearchPage() {
  const { caseId, summary } = useCase();
  const cloud = caseCloud(summary?.cloud);
  const sources = defaultFindingSources(cloud);
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
    () => paramsFromFilters(filters, cloud, params.q),
    [filters, cloud, params.q],
  );

  useEffect(() => setText(params.q ?? ""), [params.q]);
  useEffect(() => {
    try {
      setSaved(JSON.parse(localStorage.getItem(`ventra.saved.${caseId}`) || "[]"));
    } catch {
      setSaved([]);
    }
  }, [caseId]);

  const run = useCallback(
    (qv: string) => {
      write({ q: qv || undefined });
      setPage(0);
    },
    [write, setPage],
  );

  const save = useCallback(() => {
    if (!text.trim()) return;
    const next = Array.from(new Set([text, ...saved])).slice(0, 12);
    setSaved(next);
    localStorage.setItem(`ventra.saved.${caseId}`, JSON.stringify(next));
  }, [text, saved, caseId]);

  const totalQ = useQuery({
    queryKey: ["findings-total", caseId, sources],
    queryFn: () =>
      api.events(caseId, { kind: "finding", source: sources, limit: 1, offset: 0 }),
  });

  const eventsQ = useQuery({
    queryKey: ["findings", caseId, effective, page, pageSize],
    queryFn: () => api.events(caseId, { ...effective, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["findings-facets", caseId, sources],
    queryFn: () => api.facets(caseId, { kind: "finding", source: sources }),
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
    [filters, params.q, write, setPage],
  );

  const handleReset = useCallback(() => {
    setText("");
    setPage(0);
    clearAll();
  }, [clearAll, setPage]);

  return (
    <>
      <PanelHeader icon={ShieldAlert} title={panelLabel(cloud, "search")} panel="findings" />

      <PanelBody className="cloudtrail-view findings-events space-y-4">
        <FindingsToolbar
          facets={facetsQ.data}
          filters={filters}
          total={total}
          search={text}
          visibleColumns={visibleColumns}
          onChange={handleChange}
          onColumnsChange={handleColumnsChange}
          onSearchChange={setText}
          onSearchSubmit={() => run(text)}
          onSave={save}
          onReset={handleReset}
        />

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

        <div className="ct-panel">
          <FindingsTable
            events={eventsQ.data?.events ?? []}
            loading={eventsQ.isPending && !eventsQ.data}
            visibleColumns={visibleColumns}
            emptyHint={
              params.q
                ? `No findings match “${params.q}”.`
                : "No threat or compliance findings in this case — check Logs Coverage for source gaps."
            }
          />
        </div>

        <TablePager
          page={page}
          pageSize={pageSize}
          total={matched}
          shown={eventsQ.data?.events.length ?? 0}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      </PanelBody>
    </>
  );
}
