"use client";

import { Entity } from "@/components/pivot";
import { fmtDateOnly } from "@/lib/format";

export function IdentitySecretsTable({ secrets }: { secrets: any[] }) {
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
            <th>Name</th>
            <th>ARN</th>
            <th>Region</th>
            <th>Created</th>
            <th>Last accessed</th>
          </tr>
        </thead>
        <tbody>
          {secrets.map((s) => (
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
