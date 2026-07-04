"use client";

import { Button } from "@/components/ui";
import { cn } from "@/lib/utils";
import { CheckCircle2, CloudCog, Plus, ServerCog, ShieldCheck, TriangleAlert } from "lucide-react";

type ProvidersPageHeaderProps = {
  onAdd: () => void;
  total: number;
  connected: number;
  untested: number;
};

function HeaderMetric({
  label,
  value,
  icon: Icon,
  tone = "default",
}: {
  label: string;
  value: number | string;
  icon: typeof CloudCog;
  tone?: "default" | "ok" | "warn";
}) {
  return (
    <div className="rounded-md border border-border bg-bg/45 px-3 py-2.5">
      <div className="flex items-center gap-2 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">
        <Icon
          className={cn(
            "h-3.5 w-3.5",
            tone === "ok" && "text-ok-green",
            tone === "warn" && "text-warn-amber",
          )}
        />
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value}</div>
    </div>
  );
}

export function ProvidersPageHeader({
  onAdd,
  total,
  connected,
  untested,
}: ProvidersPageHeaderProps) {
  return (
    <section className="mb-6 overflow-hidden rounded-md border border-border bg-surface">
      <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div>
          <div className="mb-2 inline-flex items-center gap-2 rounded-md border border-accent/25 bg-accent/10 px-2.5 py-1 text-2xs font-semibold uppercase tracking-wide text-accent">
            <ServerCog className="h-3.5 w-3.5" />
            Server-side collection
          </div>
          <h1 className="page-title">Cloud connections</h1>
          <p className="page-subtitle">
            Connect AWS, Azure, GCP, and Microsoft 365 accounts to the Ventra backend. The browser
            stores no secrets; Ventra only records provider scope and the credential method it should
            use on the server.
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            <Button variant="primary" icon={Plus} onClick={onAdd}>
              Add connection
            </Button>
            <div className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/45 px-3 py-2 text-sm text-fg-subtle">
              <ShieldCheck className="h-4 w-4 text-accent" />
              Test validates the backend credential chain
            </div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 lg:grid-cols-1">
          <HeaderMetric label="Saved" value={total} icon={CloudCog} />
          <HeaderMetric label="Healthy" value={connected} icon={CheckCircle2} tone="ok" />
          <HeaderMetric label="Needs test" value={untested} icon={TriangleAlert} tone="warn" />
        </div>
      </div>
    </section>
  );
}
