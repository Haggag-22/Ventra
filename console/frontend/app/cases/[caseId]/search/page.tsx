"use client";

import { useCase } from "@/components/case-context";
import { EventsTable } from "@/components/events-table";
import { FilterRail } from "@/components/filter-rail";
import { PanelHeader } from "@/components/panel";
import { Button, Card, Input, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtNum } from "@/lib/format";
import { useFilters } from "@/lib/useFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Bookmark, Search, ShieldAlert, Star } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

const EXAMPLES = ["UnauthorizedAccess", "Recon", "Policy:AWS", "GuardDuty", "FAILED"];

const FINDING_SOURCES = ["guardduty", "securityhub", "macie", "detective"];

export default function SearchPage() {
  const { caseId } = useCase();
  const { params, setParam } = useFilters();
  const [text, setText] = useState(params.q ?? "");
  const [saved, setSaved] = useState<string[]>([]);
  const [page, setPage] = useState(0);

  const scoped = useMemo(
    () => ({
      ...params,
      kind: "finding",
      source: params.source?.length ? params.source : FINDING_SOURCES,
    }),
    [params],
  );

  useEffect(() => setText(params.q ?? ""), [params.q]);
  useEffect(() => {
    try {
      setSaved(JSON.parse(localStorage.getItem(`harbor.saved.${caseId}`) || "[]"));
    } catch {
      setSaved([]);
    }
  }, [caseId]);

  const run = (qv: string) => {
    setParam("q", qv || undefined);
    setPage(0);
  };
  const save = () => {
    if (!text.trim()) return;
    const next = Array.from(new Set([text, ...saved])).slice(0, 12);
    setSaved(next);
    localStorage.setItem(`harbor.saved.${caseId}`, JSON.stringify(next));
  };

  const eventsQ = useQuery({
    queryKey: ["findings", caseId, scoped, page],
    queryFn: () => api.events(caseId, { ...scoped, limit: 200, offset: page * 200 }),
    placeholderData: keepPreviousData,
  });
  const facetsQ = useQuery({
    queryKey: ["findings-facets", caseId, scoped],
    queryFn: () => api.facets(caseId, scoped),
  });

  return (
    <div className="flex h-full">
      <FilterRail facets={facetsQ.data} />
      <div className="flex min-w-0 flex-1 flex-col">
        <PanelHeader
          icon={ShieldAlert}
          title="Security Findings"
          panel="findings"
          actions={
            <span className="text-xs text-fg-subtle">
              {eventsQ.isFetching ? <Spinner /> : `${fmtNum(eventsQ.data?.total ?? 0)} findings`}
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
                placeholder="Search findings — title, type, resource, severity…"
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

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-fg-subtle">Try:</span>
            {EXAMPLES.map((ex) => (
              <button key={ex} onClick={() => { setText(ex); run(ex); }} className="chip hover:text-accent">
                {ex}
              </button>
            ))}
          </div>

          {saved.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Star className="h-3.5 w-3.5 text-fg-subtle" />
              {saved.map((sv) => (
                <button
                  key={sv}
                  onClick={() => { setText(sv); run(sv); }}
                  className="chip border-accent/20 hover:text-accent"
                >
                  {sv}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-6">
          <Card className="overflow-hidden">
            <EventsTable
              events={eventsQ.data?.events ?? []}
              loading={eventsQ.isLoading}
              compact
              showFindingSource
              emptyHint={
                params.q
                  ? `No findings match “${params.q}”.`
                  : "No threat or compliance findings in this case — check Collection Coverage for collector gaps."
              }
            />
          </Card>
        </div>
      </div>
    </div>
  );
}
