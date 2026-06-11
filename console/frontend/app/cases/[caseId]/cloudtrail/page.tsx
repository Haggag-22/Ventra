"use client";

import { useCase } from "@/components/case-context";
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

const PAGE = 100;
const BASE_SOURCE = ["cloudtrail", "sts"];

function filtersFromParams(params: EventParams): CloudTrailFilters {
  return {
    q: params.q,
    actions: params.actions,
    services: params.services,
    regions: params.regions,
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
  const [visibleColumns, setVisibleColumns] = useState<CloudTrailColKey[]>(
    ALL_CLOUDTRAIL_COL_KEYS,
  );

  useEffect(() => {
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
    queryKey: ["ct-events", caseId, effective, page],
    queryFn: () => api.events(caseId, { ...effective, limit: PAGE, offset: page * PAGE }),
    placeholderData: keepPreviousData,
  });

  const facetsQ = useQuery({
    queryKey: ["ct-facets", caseId],
    queryFn: () => api.facets(caseId, { source: BASE_SOURCE }),
  });

  const total = totalQ.data?.total ?? 0;
  const matched = eventsQ.data?.total ?? 0;
  const offset = page * PAGE;
  const pageEnd = Math.min(offset + PAGE, matched);

  const handleChange = useCallback(
    (next: Partial<CloudTrailFilters>) => {
      const merged = { ...filters, ...next };
      write({
        q: merged.q,
        source: BASE_SOURCE,
        actions: merged.actions,
        services: merged.services,
        regions: merged.regions,
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
            loading={eventsQ.isLoading}
            visibleColumns={visibleColumns}
          />
        </div>

        {matched > PAGE && (
          <div className="ct-pager">
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
          </div>
        )}
      </PanelBody>
    </>
  );
}
