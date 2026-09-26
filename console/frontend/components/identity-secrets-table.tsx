"use client";

import { Entity } from "@/components/pivot";
import { SortLabel, timeValue, useClientSort, type SortValue } from "@/components/sort-header";
import { fmtDateOnly } from "@/lib/format";

const COLS = [
  { key: "name", label: "Name" },
  { key: "arn", label: "ARN" },
  { key: "region", label: "Region" },
  { key: "created", label: "Created" },
  { key: "last_accessed", label: "Last accessed" },
] as const;

function secretValue(s: any, key: string): SortValue {
  switch (key) {
    case "name":
      return s.Name;
    case "arn":
      return s.ARN;
    case "region":
      return s._ventra_region;
    case "created":
      return timeValue(s.CreatedDate);
    case "last_accessed":
      return timeValue(s.LastAccessedDate);
    default:
      return null;
  }
}

export function IdentitySecretsTable({ secrets }: { secrets: any[] }) {
  const { sorted, sort, toggle } = useClientSort(secrets ?? [], secretValue);
  if (!secrets || secrets.length === 0) {
    return (
      <div className="px-4 py-16 text-center text-sm text-fg-subtle">No secrets collected.</div>
    );
  }

  return (
    <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
      <table className="ct-table ct-table-no-row-click w-full border-collapse text-left">
        <thead className="sticky top-0 z-10">
          <tr>
            {COLS.map((c) => (
              <th key={c.key}>
                <SortLabel label={c.label} sortKey={c.key} sort={sort} onSort={toggle} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((s) => (
            <tr key={s.ARN ?? s.Name}>
              <td className="truncate">
                <Entity kind="resource" value={s.Name} truncate />
              </td>
              <td className="mono truncate text-xs text-fg-subtle">{s.ARN || "—"}</td>
              <td className="mono text-xs text-fg-subtle">{s._ventra_region || "—"}</td>
              <td className="mono text-xs text-fg-subtle">{fmtDateOnly(s.CreatedDate)}</td>
              <td className="mono text-xs text-fg-subtle">
                {s.LastAccessedDate ? fmtDateOnly(s.LastAccessedDate) : "never"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
