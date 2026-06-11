/** Normalize IAM snapshot policy attachments for the Identity panel. */

export type IamPolicyKind =
  | "managed"
  | "inline"
  | "trust"
  | "group-managed"
  | "group-inline"
  | "boundary";

export interface IamPolicyEntry {
  name: string;
  kind: IamPolicyKind;
  arn?: string;
  /** Group name when inherited via group membership. */
  viaGroup?: string;
  document: unknown;
}

type IamRecord = Record<string, unknown>;
type IamGroup = IamRecord & { GroupName?: string };

function managedEntries(
  items: unknown[],
  kind: IamPolicyKind,
  viaGroup?: string,
): IamPolicyEntry[] {
  const out: IamPolicyEntry[] = [];
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const p = item as IamRecord;
    const name = String(p.PolicyName ?? "");
    if (!name) continue;
    out.push({
      name,
      kind,
      arn: typeof p.PolicyArn === "string" ? p.PolicyArn : undefined,
      viaGroup,
      document: p.PolicyDocument ?? { note: "Policy document not collected" },
    });
  }
  return out;
}

function inlineEntries(items: unknown[], kind: IamPolicyKind, viaGroup?: string): IamPolicyEntry[] {
  const out: IamPolicyEntry[] = [];
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const p = item as IamRecord;
    const name = String(p.PolicyName ?? "");
    if (!name) continue;
    out.push({
      name,
      kind,
      viaGroup,
      document: p.PolicyDocument ?? {},
    });
  }
  return out;
}

function boundaryEntry(record: IamRecord): IamPolicyEntry | null {
  const boundary = record.PermissionsBoundary as IamRecord | undefined;
  if (!boundary?.PermissionsBoundaryArn) return null;
  return {
    name: String(boundary.PermissionsBoundaryArn).split("/").pop() ?? "permissions-boundary",
    kind: "boundary",
    arn: String(boundary.PermissionsBoundaryArn),
    document: boundary.PolicyDocument ?? { arn: boundary.PermissionsBoundaryArn },
  };
}

export function policiesForUser(user: IamRecord, groups: IamGroup[] = []): IamPolicyEntry[] {
  const out: IamPolicyEntry[] = [
    ...managedEntries((user.AttachedManagedPolicies as unknown[]) ?? [], "managed"),
    ...inlineEntries((user.UserPolicyList as unknown[]) ?? [], "inline"),
  ];

  const boundary = boundaryEntry(user);
  if (boundary) out.push(boundary);

  const byName = new Map(groups.map((g) => [g.GroupName, g]));
  for (const gname of (user.GroupList as string[]) ?? []) {
    const group = byName.get(gname);
    if (!group) continue;
    out.push(
      ...managedEntries(
        (group.AttachedManagedPolicies as unknown[]) ?? [],
        "group-managed",
        gname,
      ),
      ...inlineEntries((group.GroupPolicyList as unknown[]) ?? [], "group-inline", gname),
    );
  }

  return out;
}

export function policiesForRole(role: IamRecord): IamPolicyEntry[] {
  const out: IamPolicyEntry[] = [
    ...managedEntries((role.AttachedManagedPolicies as unknown[]) ?? [], "managed"),
    ...inlineEntries((role.RolePolicyList as unknown[]) ?? [], "inline"),
  ];

  if (role.AssumeRolePolicyDocument) {
    out.unshift({
      name: "Trust policy",
      kind: "trust",
      document: role.AssumeRolePolicyDocument,
    });
  }

  const boundary = boundaryEntry(role);
  if (boundary) out.push(boundary);

  return out;
}

export function policyKindLabel(kind: IamPolicyKind): string {
  switch (kind) {
    case "managed":
      return "Managed";
    case "inline":
      return "Inline";
    case "trust":
      return "Trust";
    case "group-managed":
      return "Group · managed";
    case "group-inline":
      return "Group · inline";
    case "boundary":
      return "Permissions boundary";
  }
}
