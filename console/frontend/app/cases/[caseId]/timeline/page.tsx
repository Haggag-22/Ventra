"use client";

import { useCase } from "@/components/case-context";
import { EventsTable } from "@/components/events-table";
import { FilterRail } from "@/components/filter-rail";
import { PanelHeader } from "@/components/panel";
import { TimelineChart } from "@/components/timeline-chart";
import { Button, Card, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum } from "@/lib/format";
import { usePagination } from "@/lib/pagination";
import { TablePager } from "@/components/table-pager";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Activity, X } from "lucide-react";

export default function TimelinePage() {
  const { caseId } = useCase();
  const { params, setParam } = useFilters();
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.timeline.page-size");

  const eventsQ = useQuery({
    queryKey: ["events", caseId, params, page, pageSize],
    queryFn: () => api.events(caseId, { ...params, limit: pageSize, offset: page * pageSize }),
    placeholderData: keepPreviousData,
  });
  const facetsQ = useQuery({
    queryKey: ["facets", caseId, params],
    queryFn: () => api.facets(caseId, params),
  });
  const timelineQ = useQuery({
    queryKey: ["timeline", caseId, params],
    queryFn: () => api.timeline(caseId, params),
  });

  const total = eventsQ.data?.total ?? 0;
  const hasWindow = params.since || params.until;

  return (
    <div className="flex h-full">
      <FilterRail facets={facetsQ.data} />
      <div className="flex min-w-0 flex-1 flex-col">
        <PanelHeader
          icon={Activity}
          title="Timeline"
          description="Every source on one axis. Drag to zoom into a window."
          actions={
            <span className="text-xs text-fg-subtle">
              {eventsQ.isFetching ? <Spinner /> : `${fmtNum(total)} events`}
            </span>
          }
        />

        <div className="border-b border-border bg-surface px-4 py-3">
          {hasWindow && (
            <div className="mb-2 flex items-center gap-2">
              <span className="chip text-accent border-accent/30 bg-accent/10">
                Window: {params.since ?? "start"} → {params.until ?? "end"}
              </span>
              <Button
                size="sm"
                variant="ghost"
                icon={X}
                onClick={() => {
                  setParam("since");
                  setParam("until");
                }}
              >
                Reset zoom
              </Button>
            </div>
          )}
          {timelineQ.data ? (
            <TimelineChart
              points={timelineQ.data.points}
              min={timelineQ.data.min}
              max={timelineQ.data.max}
              onBrush={(since, until) => {
                setParam("since", since);
                setParam("until", until);
                setPage(0);
              }}
            />
          ) : (
            <div className="flex h-[200px] items-center justify-center">
              <Spinner />
            </div>
          )}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          <Card className="m-4 overflow-hidden">
            <EventsTable
              events={eventsQ.data?.events ?? []}
              loading={eventsQ.isLoading}
              sort={params.sort ?? "timestamp"}
              order={params.order ?? "asc"}
              onSort={(col) => {
                const desc = params.sort === col && params.order !== "desc";
                setParam("sort", col);
                setParam("order", desc ? "desc" : "asc");
              }}
            />
            <TablePager
              page={page}
              pageSize={pageSize}
              total={total}
              shown={eventsQ.data?.events.length ?? 0}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
            />
          </Card>
        </div>
      </div>
    </div>
  );
}
