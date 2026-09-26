"use client";

import { SortTh, useClientSort } from "@/components/sort-header";
import { fmtNum } from "@/lib/format";
import type { CloudWatchCollection } from "@/lib/types";

type LogGroup = NonNullable<CloudWatchCollection["log_groups"]>[number];

const groupValue = (g: LogGroup, key: string) =>
  key === "records" ? (g.records ?? 0) : key === "region" ? g.region : g.name;

export function CloudWatchCollectionSummary({ data }: { data: CloudWatchCollection }) {
  const groups = data.log_groups ?? [];
  const { sorted, sort, toggle } = useClientSort(groups, groupValue);

  if (groups.length === 0) {
    return (
      <p className="text-xs text-fg-subtle">
        No CloudWatch log groups were recorded for this case. Re-run collection with the
        CloudWatch collector and CloudWatch log group parameters.
      </p>
    );
  }

  return (
    <table className="w-full table-fixed text-sm">
      <colgroup>
        <col className="w-[60%]" />
        <col className="w-[20%]" />
        <col className="w-[20%]" />
      </colgroup>
      <thead>
        <tr>
          <SortTh label="Log group" sortKey="name" sort={sort} onSort={toggle} className="pl-0" />
          <SortTh label="Region" sortKey="region" sort={sort} onSort={toggle} />
          <SortTh label="Records" sortKey="records" sort={sort} onSort={toggle} align="right" className="pr-0" />
        </tr>
      </thead>
      <tbody>
        {sorted.map((g) => (
          <tr key={`${g.region}:${g.name}`} className="border-t border-border/50">
            <td className="table-cell pl-0">
              <span className="mono break-all text-fg" title={g.arn || g.name}>
                {g.name || "—"}
              </span>
            </td>
            <td className="table-cell-muted mono">{g.region || "—"}</td>
            <td className="table-cell !text-right mono pr-0">{fmtNum(g.records ?? 0)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
