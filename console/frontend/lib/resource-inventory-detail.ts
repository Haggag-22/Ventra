import type { InventoryResourceItem } from "./types";

export type ResourceRow = Record<string, unknown>;

export type ResourceColumn = {
  key: string;
  header: string;
  cell: (row: ResourceRow) => string;
  mono?: boolean;
  min?: number;
};

function col(
  key: string,
  header: string,
  cell: (row: ResourceRow) => string,
  opts?: { mono?: boolean; min?: number },
): ResourceColumn {
  return { key, header, cell, mono: opts?.mono, min: opts?.min ?? 80 };
}

function str(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  return String(v);
}

function region(row: ResourceRow): string {
  return str(row._ventra_region ?? row.region);
}

function boolLabel(v: unknown, yes = "yes", no = "no"): string {
  if (v === true) return yes;
  if (v === false) return no;
  return "—";
}

export const RESOURCE_COLUMNS: Record<string, ResourceColumn[]> = {
  ec2_instances: [
    col("instance_id", "Instance ID", (r) => str(r.InstanceId), { mono: true, min: 130 }),
    col("type", "Type", (r) => str(r.InstanceType), { min: 90 }),
    col("state", "State", (r) => str((r.State as { Name?: string })?.Name), { min: 80 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
    col("private_ip", "Private IP", (r) => str(r.PrivateIpAddress), { mono: true, min: 110 }),
    col("public_ip", "Public IP", (r) => str(r.PublicIpAddress), { mono: true, min: 110 }),
    col("ami", "AMI", (r) => str(r.ImageId), { mono: true, min: 120 }),
  ],
  ec2_volumes: [
    col("volume_id", "Volume ID", (r) => str(r.VolumeId), { mono: true, min: 130 }),
    col("size", "Size (GiB)", (r) => str(r.Size), { min: 80 }),
    col("state", "State", (r) => str(r.State), { min: 80 }),
    col("encrypted", "Encrypted", (r) => boolLabel(r.Encrypted), { min: 80 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  ec2_snapshots: [
    col("snapshot_id", "Snapshot ID", (r) => str(r.SnapshotId), { mono: true, min: 150 }),
    col("size", "Size (GiB)", (r) => str(r.VolumeSize ?? r.Size), { min: 80 }),
    col("encrypted", "Encrypted", (r) => boolLabel(r.Encrypted), { min: 80 }),
    col("shared", "Shared", (r) => boolLabel(r.Shared ?? r._ventra_shared), { min: 70 }),
    col("description", "Description", (r) => str(r.Description), { min: 160 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  ec2_images: [
    col("ami_id", "AMI ID", (r) => str(r.ImageId), { mono: true, min: 130 }),
    col("name", "Name", (r) => str(r.Name), { min: 140 }),
    col("state", "State", (r) => str(r.State), { min: 80 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  ec2_launch_templates: [
    col("template_id", "Template ID", (r) => str(r.LaunchTemplateId), { mono: true, min: 140 }),
    col("name", "Name", (r) => str(r.LaunchTemplateName), { min: 160 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  lambda_functions: [
    col("function", "Function", (r) => str(r.FunctionName), { min: 160 }),
    col("runtime", "Runtime", (r) => str(r.Runtime), { min: 90 }),
    col("handler", "Handler", (r) => str(r.Handler), { min: 140 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
    col("arn", "ARN", (r) => str(r.FunctionArn), { mono: true, min: 220 }),
  ],
  s3_buckets: [
    col("bucket", "Bucket", (r) => str(r.name), { min: 180 }),
    col("region", "Region", (r) => str(r.region), { min: 100 }),
    {
      key: "public",
      header: "Public",
      min: 80,
      cell: (r) =>
        boolLabel(
          r._ventra_public ?? (r.policy_status as { IsPublic?: boolean })?.IsPublic,
          "public",
          "private",
        ),
    },
    {
      key: "logging",
      header: "Access logging",
      min: 140,
      cell: (r) =>
        r._ventra_no_access_logging || !r.logging
          ? "none"
          : str((r.logging as { TargetBucket?: string })?.TargetBucket),
    },
  ],
  vpc_count: [
    col("vpc_id", "VPC ID", (r) => str(r.VpcId), { mono: true, min: 140 }),
    col("cidr", "CIDR", (r) => str(r.CidrBlock), { mono: true, min: 120 }),
    col("default", "Default", (r) => boolLabel(r.IsDefault), { min: 70 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  vpc_flow_logs: [
    col("flow_log_id", "Flow log ID", (r) => str(r.FlowLogId), { mono: true, min: 150 }),
    col("resource", "Resource", (r) => str(r.ResourceId), { mono: true, min: 140 }),
    col("destination", "Destination", (r) => str(r.LogDestinationType), { min: 120 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  ec2_enis: [
    col("eni_id", "ENI ID", (r) => str(r.NetworkInterfaceId), { mono: true, min: 150 }),
    col("status", "Status", (r) => str(r.Status), { min: 80 }),
    col("private_ip", "Private IP", (r) => str(r.PrivateIpAddress), { mono: true, min: 110 }),
    col("subnet", "Subnet", (r) => str(r.SubnetId), { mono: true, min: 140 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  ec2_security_groups: [
    col("group_id", "Group ID", (r) => str(r.GroupId), { mono: true, min: 130 }),
    col("name", "Name", (r) => str(r.GroupName), { min: 120 }),
    col("vpc", "VPC", (r) => str(r.VpcId), { mono: true, min: 140 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  waf_acls: [
    col("name", "Name", (r) => str(r.Name), { min: 160 }),
    col("id", "ID", (r) => str(r.Id), { mono: true, min: 200 }),
    col("scope", "Scope", (r) => str(r._ventra_scope ?? r.Scope), { min: 90 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
  ],
  iam_users: [
    col("user", "User", (r) => str(r.UserName), { min: 120 }),
    col("arn", "ARN", (r) => str(r.Arn), { mono: true, min: 240 }),
    {
      key: "active_keys",
      header: "Active keys",
      min: 90,
      cell: (r) =>
        String(
          ((r.AccessKeys as { Status?: string }[]) ?? []).filter((k) => k.Status === "Active")
            .length,
        ),
    },
    {
      key: "mfa",
      header: "MFA",
      min: 60,
      cell: (r) => (((r.MFADevices as unknown[]) ?? []).length > 0 ? "yes" : "no"),
    },
  ],
  iam_roles: [
    col("role", "Role", (r) => str(r.RoleName), { min: 140 }),
    col("arn", "ARN", (r) => str(r.Arn), { mono: true, min: 240 }),
    {
      key: "managed_policies",
      header: "Managed policies",
      min: 120,
      cell: (r) => String(((r.AttachedManagedPolicies as unknown[]) ?? []).length),
    },
  ],
  iam_groups: [
    col("group", "Group", (r) => str(r.GroupName), { min: 120 }),
    col("arn", "ARN", (r) => str(r.Arn), { mono: true, min: 240 }),
  ],
  iam_policies: [
    col("policy", "Policy", (r) => str(r.PolicyName), { min: 160 }),
    col("arn", "ARN", (r) => str(r.Arn), { mono: true, min: 240 }),
  ],
  kms_keys: [
    col("key_id", "Key ID", (r) => str(r.key_id), { mono: true, min: 200 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
    {
      key: "manager",
      header: "Manager",
      min: 100,
      cell: (r) => str((r.metadata as { KeyManager?: string })?.KeyManager),
    },
    {
      key: "state",
      header: "State",
      min: 90,
      cell: (r) => str((r.metadata as { KeyState?: string })?.KeyState),
    },
  ],
  secrets: [
    col("name", "Name", (r) => str(r.Name), { min: 160 }),
    col("arn", "ARN", (r) => str(r.ARN), { mono: true, min: 240 }),
    col("region", "Region", (r) => region(r), { min: 100 }),
    col("rotation", "Rotation", (r) => boolLabel(r.RotationEnabled), { min: 80 }),
  ],
};

export function resourceWidthsKey(itemId: string): string {
  return `ventra.resource-table.widths.${itemId}`;
}

export function defaultResourceWidths(columns: ResourceColumn[]): Record<string, number> {
  return Object.fromEntries(columns.map((c) => [c.key, c.min ?? 100]));
}

export function loadResourceWidths(
  itemId: string,
  columns: ResourceColumn[],
): Record<string, number> {
  const defaults = defaultResourceWidths(columns);
  if (typeof window === "undefined") return defaults;
  try {
    const raw = localStorage.getItem(resourceWidthsKey(itemId));
    if (!raw) return defaults;
    return { ...defaults, ...JSON.parse(raw) };
  } catch {
    return defaults;
  }
}

export function getInventoryRows(data: unknown, key: string): ResourceRow[] {
  if (!data || typeof data !== "object") return [];
  let node: unknown = data;
  for (const part of key.split(".")) {
    if (!node || typeof node !== "object") return [];
    node = (node as Record<string, unknown>)[part];
  }
  if (Array.isArray(node)) {
    if (node.length > 0 && typeof node[0] === "string") {
      return node.map((region) => ({ region }));
    }
    return node as ResourceRow[];
  }
  return [];
}

export function resourcePrimaryId(item: InventoryResourceItem, row: ResourceRow): string {
  const id =
    row.InstanceId ??
    row.VolumeId ??
    row.SnapshotId ??
    row.ImageId ??
    row.LaunchTemplateId ??
    row.FunctionName ??
    row.name ??
    row.VpcId ??
    row.FlowLogId ??
    row.NetworkInterfaceId ??
    row.GroupId ??
    row.Name ??
    row.UserName ??
    row.RoleName ??
    row.GroupName ??
    row.PolicyName ??
    row.key_id ??
    row.ARN ??
    row.region ??
    row.Id;
  return String(id ?? "row");
}

export function columnsForResource(itemId: string): ResourceColumn[] {
  return (
    RESOURCE_COLUMNS[itemId] ?? [
      col("name", "Name", (r) => resourcePrimaryId({ id: itemId } as InventoryResourceItem, r)),
    ]
  );
}
