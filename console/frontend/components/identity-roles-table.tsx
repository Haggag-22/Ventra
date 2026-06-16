"use client";

import { IdentityPrincipal } from "@/components/identity-principal";
import { TablePager } from "@/components/table-pager";
import { fmtDateOnly } from "@/lib/format";
import { policiesForRole } from "@/lib/iam-policies";
import { usePagination } from "@/lib/pagination";
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

const WIDTHS_KEY = "ventra.identity-roles-table.widths";

export function IdentityRolesTable({ roles }: { roles: any[] }) {
  const { startResize, colWidth, totalWidth } = useResizableColumns(COLS, DEFAULT_WIDTHS, WIDTHS_KEY);
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.identity-roles.page-size");

  if (roles.length === 0) {
    return (
      <div className="px-4 py-16 text-center text-sm text-fg-subtle">No roles collected.</div>
    );
  }

  const paged = roles.slice(page * pageSize, page * pageSize + pageSize);

  return (
    <>
    <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
      <table
        className="ct-table ct-table-no-row-click w-full border-collapse text-left"
        style={{ tableLayout: "fixed", width: totalWidth, minWidth: "100%" }}
      >
        <colgroup>
          {COLS.map((c) => (
            <col key={c.key} style={{ width: colWidth(c.key) }} />
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
          {paged.map((r) => (
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
    <TablePager
      page={page}
      pageSize={pageSize}
      total={roles.length}
      shown={paged.length}
      onPageChange={setPage}
      onPageSizeChange={setPageSize}
    />
    </>
  );
}
