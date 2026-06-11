"use client";

import { IdentityPrincipal } from "@/components/identity-principal";
import { fmtDateOnly } from "@/lib/format";
import { policiesForRole } from "@/lib/iam-policies";
import { useResizableColumns } from "@/lib/resizable-columns";

const COLS = [
  { key: "role", label: "Role", min: 200 },
  { key: "created", label: "Created", min: 100 },
] as const;

type ColKey = (typeof COLS)[number]["key"];

const DEFAULT_WIDTHS: Record<ColKey, number> = {
  role: 520,
  created: 120,
};

const WIDTHS_KEY = "harbor.identity-roles-table.widths";

export function IdentityRolesTable({ roles }: { roles: any[] }) {
  const { startResize, colPct } = useResizableColumns(COLS, DEFAULT_WIDTHS, WIDTHS_KEY);

  if (roles.length === 0) {
    return (
      <div className="px-4 py-16 text-center text-sm text-fg-subtle">No roles collected.</div>
    );
  }

  return (
    <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
      <table
        className="ct-table ct-table-no-row-click w-full border-collapse text-left"
        style={{ tableLayout: "fixed" }}
      >
        <colgroup>
          {COLS.map((c) => (
            <col key={c.key} style={{ width: colPct(c.key) }} />
          ))}
        </colgroup>
        <thead className="sticky top-0 z-10">
          <tr>
            {COLS.map((c) => (
              <th key={c.key} className="relative">
                <span className="block truncate pr-2">{c.label}</span>
                <span
                  role="separator"
                  aria-orientation="vertical"
                  aria-label={`Resize ${c.label} column`}
                  onMouseDown={(e) => startResize(c.key, e)}
                  onClick={(e) => e.stopPropagation()}
                  className="ct-col-resize"
                />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {roles.map((r) => (
            <tr key={r.RoleName}>
              <td className="truncate">
                <IdentityPrincipal
                  label={r.Arn ?? r.RoleName}
                  principalType="role"
                  policies={policiesForRole(r)}
                />
              </td>
              <td className="mono truncate text-fg-subtle">{fmtDateOnly(r.CreateDate)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
