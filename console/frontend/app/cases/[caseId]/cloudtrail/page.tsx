"use client";

import { useCase } from "@/components/case-context";
import { CloudTrailCollectionSummary } from "@/components/cloudtrail-collection-summary";
import { CloudTrailTable } from "@/components/cloudtrail-table";
import { CloudTrailToolbar,
  type CloudTrailFilters,
} from "@/components/cloudtrail-toolbar";
import { PanelBody, PanelHeader } from "@/components/panel";
import { api, type EventParams } from "@/lib/api";
import {
  ALL_CLOUDTRAIL_COL_KEYS,
  CLOUDTRAIL_VISIBLE_COLS_KEY,
  loadVisibleCloudTrailCols,
  type CloudTrailColKey,
} from "@/lib/cloudtrail-columns";
import { fmtNum } from "@/lib/format";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const PAGE_SIZE_OPTIONS = [100, 250, 500] as const;
const DEFAULT_PAGE_SIZE = 500;
const PAGE_SIZE_KEY = "ventra.cloudtrail.page-size";
const BASE_SOURCE = ["cloudtrail"];

function loadPageSize(): number {
  if (typeof window === "undefined") return DEFAULT_PAGE_SIZE;
  try {
    const raw = localStorage.getItem(PAGE_SIZE_KEY);
    const n = raw ? Number.parseInt(raw, 10) : DEFAULT_PAGE_SIZE;
    return PAGE_SIZE_OPTIONS.includes(n as (typeof PAGE_SIZE_OPTIONS)[number])
      ? n
      : DEFAULT_PAGE_SIZE;
  } catch {
    return DEFAULT_PAGE_SIZE;
  }
}

function filtersFromParams(params: EventParams): CloudTrailFilters {
  return {
    q: params.q,
    actions: params.actions,
    services: params.services,
    regions: params.regions,
    users: params.users,
    order: params.order ?? "desc",
    user: params.user,
    ip: params.ip,
  };
}

function paramsFromFilters(filters: CloudTrailFilters): EventParams {
  return {
    q: filters.q,
    source: BASE_SOURCE,
    actions: filters.actions,
    services: filters.services,
    regions: filters.regions,
    users: filters.users,
    user: filters.user,
    ip: filters.ip,
    sort: "timestamp",
    order: filters.order ?? "desc",
  };
}

export default function CloudTrailPage() {
  const { caseId } = useCase();
  const { params, write, clearAll } = useFilters();
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [visibleColumns, setVisibleColumns] = useState<CloudTrailColKey[]>(
    ALL_CLOUDTRAIL_COL_KEYS,
  );

  useEffect(() => {
    setPageSize(loadPageSize());
    setVisibleColumns(loadVisibleCloudTrailCols());
  }, []);

  const handleColumnsChange = useCallback((cols: CloudTrailColKey[]) => {
    setVisibleColumns(cols);
    try {
      localStorage.setItem(CLOUDTRAIL_VISIBLE_COLS_KEY, JSON.stringify(cols));
    } catch {
      /* ignore */
    }
  }, []);

  const filters = useMemo(() => filtersFromParams(params), [params]);
  const effective = useMemo(() => paramsFromFilters(filters), [filters]);

  const totalQ = useQuery({
    queryKey: ["ct-total", caseId],
    queryFn: () => api.events(caseId, { source: BASE_SOURCE, limit: 1, offset: 0 }),
  });

  const eventsQ = useQuery({
    queryKey: ["ct-events", caseId, effective, page, pageSize],
    queryFn: () =>
      api.events(caseId, { ...effective, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["ct-facets", caseId],
    queryFn: () => api.facets(caseId, { source: BASE_SOURCE }),
  });

  const total = totalQ.data?.total ?? 0;
  const matched = eventsQ.data?.total ?? 0;
  const eventsFailed = totalQ.isError || eventsQ.isError;
  const offset = page * pageSize;
  const pageEnd = Math.min(offset + pageSize, matched);

  const handlePageSizeChange = useCallback((next: number) => {
    setPageSize(next);
    setPage(0);
    try {
      localStorage.setItem(PAGE_SIZE_KEY, String(next));
    } catch {
      /* ignore */
    }
  }, []);

  const handleChange = useCallback(
    (next: Partial<CloudTrailFilters>) => {
      const merged = { ...filters, ...next };
      write({
        q: merged.q,
        source: BASE_SOURCE,
        actions: merged.actions,
        services: merged.services,
        regions: merged.regions,
        users: merged.users,
        user: merged.user,
        ip: merged.ip,
        order: merged.order ?? "desc",
        sort: "timestamp",
      });
      setPage(0);
    },
    [filters, write],
  );

  const handleApply = useCallback(() => {
    write({
      user: filters.user,
      ip: filters.ip,
    });
    setPage(0);
  }, [filters, write]);

  const handleReset = useCallback(() => {
    setPage(0);
    clearAll();
  }, [clearAll]);

  return (
    <>
      <PanelHeader icon={ScrollText} title="CloudTrail Timeline" panel="cloudtrail" />
      <PanelBody className="cloudtrail-view space-y-4">
        <CloudTrailCollectionPanel caseId={caseId} />

        {eventsFailed && (
          <div className="rounded-lg border border-bad-red/30 bg-bad-red/10 px-4 py-3 text-sm text-bad-red">
            Could not load CloudTrail events from the case store. Restart the backend after upgrading,
            or re-import the case with <span className="mono">make ingest</span>.
          </div>
        )}

        <CloudTrailToolbar
          facets={facetsQ.data}
          filters={filters}
          total={total}
          matched={matched}
          visibleColumns={visibleColumns}
          onChange={handleChange}
          onColumnsChange={handleColumnsChange}
          onApply={handleApply}
          onReset={handleReset}
        />

        <div className="ct-panel">
          <CloudTrailTable
            events={eventsQ.data?.events ?? []}
            loading={eventsQ.isPending && !eventsQ.data}
            visibleColumns={visibleColumns}
          />
        </div>

        <div className="ct-pager">
          {matched > pageSize && (
            <>
              <button
                type="button"
                className="ct-btn"
                disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
              >
                ← Prev
              </button>
              <span>
                {fmtNum(offset + 1)}–{fmtNum(pageEnd)} of {fmtNum(matched)}
              </span>
              <button
                type="button"
                className="ct-btn"
                disabled={pageEnd >= matched}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </button>
            </>
          )}
          <label className="ml-auto flex items-center gap-2 text-xs text-fg-subtle">
            Rows per page
            <select
              className="ct-select ct-page-size"
              value={pageSize}
              onChange={(e) => handlePageSizeChange(Number.parseInt(e.target.value, 10))}
              aria-label="Rows per page"
            >
              {PAGE_SIZE_OPTIONS.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <span className="text-xs text-fg-subtle">
            Showing {fmtNum(eventsQ.data?.events.length ?? 0)} rows
          </span>
        </div>
      </PanelBody>
    </>
  );
}

function CloudTrailCollectionPanel({ caseId }: { caseId: string }) {
  const q = useQuery({
    queryKey: ["ct-collection", caseId],
    queryFn: () => api.cloudtrailCollection(caseId),
    retry: 1,
  });

  if (q.isLoading) {
    return (
      <div className="ct-panel px-4 py-6 text-sm text-fg-subtle">Loading CloudTrail collection…</div>
    );
  }

  if (q.isError || !q.data) {
    return null;
  }

  const hasTrails = (q.data.trails?.length ?? 0) > 0;
  const hasEvents =
    (q.data.events?.lookup_api?.total ?? 0) > 0 || (q.data.events?.s3?.total ?? 0) > 0;
  if (!hasTrails && !hasEvents) {
    return null;
  }

  return (
    <div className="ct-panel p-4">
      <CloudTrailCollectionSummary data={q.data} />
    </div>
  );
}
