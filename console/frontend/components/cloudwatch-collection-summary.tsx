"use client";

import { fmtNum } from "@/lib/format";
import type { CloudWatchCollection } from "@/lib/types";

export function CloudWatchCollectionSummary({ data }: { data: CloudWatchCollection }) {
  const groups = data.log_groups ?? [];

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
          <th className="table-header-cell pl-0">Log group</th>
          <th className="table-header-cell">Region</th>
          <th className="table-header-cell-right pr-0">Records</th>
        </tr>
      </thead>
      <tbody>
        {groups.map((g) => (
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
