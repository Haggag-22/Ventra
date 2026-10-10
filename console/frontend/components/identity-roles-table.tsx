"use client";

import { IdentityPrincipal } from "@/components/identity-principal";
import { SortLabel, timeValue, useClientSort, type SortValue } from "@/components/sort-header";
import { TablePager } from "@/components/table-pager";
import { fmtDateOnly } from "@/lib/format";
import { policiesForRole } from "@/lib/iam-policies";
import { usePagination } from "@/lib/pagination";
import { useResizableColumns } from "@/lib/resizable-columns";

const IAM_COLS = [
  { key: "role", label: "Role", min: 200 },
  { key: "created", label: "Created", min: 100 },
] as const;

const ASSIGNMENT_COLS = [
  { key: "role", label: "Role", min: 180 },
  { key: "principal", label: "Principal", min: 180 },
  { key: "type", label: "Type", min: 120 },
  { key: "scope", label: "Scope", min: 220 },
  { key: "created", label: "Created", min: 100 },
] as const;

type ColKey = (typeof IAM_COLS)[number]["key"] | (typeof ASSIGNMENT_COLS)[number]["key"];

const DEFAULT_WIDTHS: Record<ColKey, number> = {
  role: 240,
  created: 120,
  principal: 220,
  type: 140,
  scope: 320,
};

const WIDTHS_KEY = "ventra.identity-roles-table.widths";

function roleValue(r: any, key: string): SortValue {
  if (key === "created") return timeValue(r.CreateDate);
  if (key === "principal") return r.principal ?? "";
  if (key === "type") return r.principal_type ?? "";
  if (key === "scope") return r.scope ?? "";
  return r.RoleName ?? r.Arn;
}

export function IdentityRolesTable({
  roles,
  layout = "iam",
}: {
  roles: any[];
  /** Azure RBAC rows are assignments, not IAM role documents. */
  layout?: "iam" | "assignment";
}) {
  const cols = layout === "assignment" ? ASSIGNMENT_COLS : IAM_COLS;
  const widthsKey = layout === "assignment" ? `${WIDTHS_KEY}.assignment` : WIDTHS_KEY;
  const { startResize, colWidth, totalWidth } = useResizableColumns(cols, DEFAULT_WIDTHS, widthsKey);
  const { page, setPage, pageSize, setPageSize } = usePagination("ventra.identity-roles.page-size");
  const { sorted, sort, toggle } = useClientSort(roles, roleValue);

  if (roles.length === 0) {
    return (
      <div className="px-4 py-16 text-center text-sm text-fg-subtle">
        {layout === "assignment" ? "No role assignments collected." : "No roles collected."}
      </div>
    );
  }

  const paged = sorted.slice(page * pageSize, page * pageSize + pageSize);

  return (
    <>
    <div className="ct-table-wrap overflow-x-auto overflow-y-auto">
      <table
        className="ct-table ct-table-no-row-click w-full border-collapse text-left"
        style={{ tableLayout: "fixed", width: totalWidth, minWidth: "100%" }}
      >
        <colgroup>
          {cols.map((c) => (
            <col key={c.key} style={{ width: colWidth(c.key) }} />
          ))}
        </colgroup>
        <thead className="sticky top-0 z-10">
          <tr>
            {cols.map((c) => (
              <th key={c.key} className="relative">
                <SortLabel label={c.label} sortKey={c.key} sort={sort} onSort={toggle} />
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
            <tr key={r.assignment_id ?? r.Arn ?? r.RoleName}>
              <td className="truncate">
                <IdentityPrincipal
                  label={layout === "assignment" ? r.RoleName : (r.Arn ?? r.RoleName)}
                  principalType="role"
                  policies={policiesForRole(r)}
                  mono={layout !== "assignment"}
                />
              </td>
              {layout === "assignment" && (
                <>
                  <td className="truncate text-fg" title={r.principal_id}>
                    {r.principal || "—"}
                  </td>
                  <td className="truncate text-fg-subtle">{r.principal_type || "—"}</td>
                  <td className="mono truncate text-fg-subtle" title={r.scope}>
                    {r.scope || "—"}
                  </td>
                </>
              )}
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
