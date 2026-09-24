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

function tagName(row: ResourceRow): string {
  const tags = row.Tags as { Key?: string; Value?: string }[] | undefined;
  return str(tags?.find((t) => t.Key === "Name")?.Value);
}

export const RESOURCE_COLUMNS: Record<string, ResourceColumn[]> = {
  // --- On-prem Kubernetes -----------------------------------------------------------------
  // Rows come from the compact object index the ingester builds per kind, plus the derived
  // artefacts the collectors write (suspicious pods, images, RBAC verdicts).
  k8s_pods: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "Pod", (r) => str(r.name), { mono: true, min: 200 }),
    col("phase", "Phase", (r) => str(r.phase), { min: 90 }),
    col("node", "Node", (r) => str(r.node), { min: 110 }),
    col("service_account", "ServiceAccount", (r) => str(r.service_account), { min: 130 }),
    col("images", "Images", (r) => str(r.images), { mono: true, min: 220 }),
    col("flags", "Flagged", (r) => str(r.flags), { min: 220 }),
  ],
  k8s_nodes: [
    col("name", "Node", (r) => str(r.name), { mono: true, min: 150 }),
    col("kubelet", "Kubelet", (r) => str(r.kubelet), { min: 100 }),
    col("os", "OS image", (r) => str(r.os), { min: 200 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_namespaces: [
    col("name", "Namespace", (r) => str(r.name), { min: 170 }),
    col("pod_security", "Pod Security", (r) => str(r.pod_security), { min: 220 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_serviceaccounts: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "ServiceAccount", (r) => str(r.name), { min: 180 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_secrets: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "Secret", (r) => str(r.name), { min: 200 }),
    col("type", "Type", (r) => str(r.type), { min: 200 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_cronjobs: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "CronJob", (r) => str(r.name), { min: 180 }),
    col("schedule", "Schedule", (r) => str(r.schedule), { mono: true, min: 120 }),
    col("images", "Images", (r) => str(r.images), { mono: true, min: 200 }),
  ],
  k8s_deployments: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "Deployment", (r) => str(r.name), { min: 180 }),
    col("replicas", "Replicas", (r) => str(r.replicas), { min: 90 }),
    col("images", "Images", (r) => str(r.images), { mono: true, min: 220 }),
  ],
  k8s_daemonsets: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "DaemonSet", (r) => str(r.name), { min: 180 }),
    col("images", "Images", (r) => str(r.images), { mono: true, min: 220 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_statefulsets: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "StatefulSet", (r) => str(r.name), { min: 180 }),
    col("replicas", "Replicas", (r) => str(r.replicas), { min: 90 }),
    col("images", "Images", (r) => str(r.images), { mono: true, min: 220 }),
  ],
  k8s_jobs: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "Job", (r) => str(r.name), { min: 180 }),
    col("images", "Images", (r) => str(r.images), { mono: true, min: 220 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_services: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "Service", (r) => str(r.name), { min: 180 }),
    col("service_type", "Type", (r) => str(r.service_type), { min: 100 }),
    col("cluster_ip", "Cluster IP", (r) => str(r.cluster_ip), { mono: true, min: 120 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_pvs: [
    col("name", "PersistentVolume", (r) => str(r.name), { min: 180 }),
    col("storage_class", "Storage class", (r) => str(r.storage_class), { min: 130 }),
    col("host_path", "hostPath", (r) => str(r.host_path), { mono: true, min: 180 }),
  ],
  k8s_clusterrolebindings: [
    col("name", "ClusterRoleBinding", (r) => str(r.name), { min: 200 }),
    col("role", "Role", (r) => str(r.role), { min: 180 }),
    col("subjects", "Subjects", (r) => str(r.subjects), { min: 200 }),
    col("grants", "Grants", (r) => str(r.grants), { min: 240 }),
    col("anonymous", "Anonymous", (r) => str(r.anonymous), { min: 150 }),
  ],
  k8s_rolebindings: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "RoleBinding", (r) => str(r.name), { min: 180 }),
    col("role", "Role", (r) => str(r.role), { min: 170 }),
    col("subjects", "Subjects", (r) => str(r.subjects), { min: 180 }),
    col("grants", "Grants", (r) => str(r.grants), { min: 220 }),
  ],
  k8s_roles: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "Role", (r) => str(r.name), { min: 180 }),
    col("grants", "Grants", (r) => str(r.grants), { min: 260 }),
  ],
  k8s_clusterroles: [
    col("name", "ClusterRole", (r) => str(r.name), { min: 200 }),
    col("grants", "Grants", (r) => str(r.grants), { min: 300 }),
  ],
  k8s_mutating_webhooks: [
    col("name", "MutatingWebhookConfiguration", (r) => str(r.name), { min: 280 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_validating_webhooks: [
    col("name", "ValidatingWebhookConfiguration", (r) => str(r.name), { min: 280 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_crds: [
    col("name", "CustomResourceDefinition", (r) => str(r.name), { mono: true, min: 300 }),
    col("created", "Created", (r) => str(r.created), { min: 170 }),
  ],
  k8s_images: [
    col("image", "Image", (r) => str(r.image), { mono: true, min: 260 }),
    col("imageID", "Image ID (digest)", (r) => str(r.imageID), { mono: true, min: 220 }),
    col("trusted", "Trusted registry", (r) => boolLabel(r.trusted), { min: 120 }),
    col("pods", "Pods", (r) => str(Array.isArray(r.pods) ? r.pods.join(", ") : r.pods), { min: 220 }),
  ],
  k8s_suspicious_pods: [
    col("pod", "Pod", (r) => str(r.pod), { mono: true, min: 220 }),
    col(
      "findings",
      "Why it was flagged",
      (r) => str(Array.isArray(r.findings) ? r.findings.join(", ") : r.findings),
      { min: 340 },
    ),
  ],
  k8s_hostpath_pvs: [
    col("name", "PersistentVolume", (r) => str(r.name), { min: 180 }),
    col("path", "Host path", (r) => str(r.path), { mono: true, min: 200 }),
    col("storageClassName", "Storage class", (r) => str(r.storageClassName), { min: 130 }),
  ],
  k8s_automounting_sas: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 130 }),
    col("name", "ServiceAccount", (r) => str(r.name), { min: 170 }),
    col(
      "automount",
      "Token automounted",
      (r) => boolLabel(r.automount_service_account_token),
      { min: 140 },
    ),
    col("explicit", "Set explicitly", (r) => boolLabel(r.automount_explicit), { min: 120 }),
    col("pods", "Pods using it", (r) => str(Array.isArray(r.pods) ? r.pods.join(", ") : r.pods), { min: 220 }),
  ],
  k8s_privileged_namespaces: [
    col("namespace", "Namespace", (r) => str(r.namespace), { min: 170 }),
    col(
      "labels",
      "Pod Security Admission labels",
      (r) =>
        str(
          r.pod_security_labels && typeof r.pod_security_labels === "object"
            ? Object.entries(r.pod_security_labels as Record<string, string>)
                .map(([k, v]) => `${k.split("/").pop()}=${v}`)
                .join(", ")
            : "",
        ),
      { min: 300 },
    ),
  ],
  k8s_dangerous_bindings: [
    col("binding", "Binding", (r) => str(r.binding), { min: 240 }),
    col("role", "Role", (r) => str(r.role), { min: 180 }),
    col("grants", "Grants", (r) => str(Array.isArray(r.grants) ? r.grants.join(", ") : r.grants), { min: 280 }),
    col("subjects", "Subjects", (r) => str(Array.isArray(r.subjects) ? r.subjects.join(", ") : r.subjects), { min: 220 }),
  ],
  k8s_anonymous_bindings: [
    col("binding", "Binding", (r) => str(r.binding), { min: 220 }),
    col("subject", "Subject", (r) => str(r.subject), { min: 200 }),
    col("role", "Role", (r) => str(r.role), { min: 200 }),
  ],
  k8s_unexpected_manifests: [
    col("name", "Static pod manifest", (r) => str(r.name), { mono: true, min: 220 }),
    col("path", "Path on node", (r) => str(r.path), { mono: true, min: 300 }),
    col("sha256", "SHA-256", (r) => str(r.sha256), { mono: true, min: 200 }),
    col("bytes", "Bytes", (r) => str(r.bytes), { min: 90 }),
  ],
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
    col("arn", "ARN", (r) => str(r.FunctionArn), { mono: true, min: 480 }),
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
    col("name", "Name", (r) => tagName(r), { min: 140 }),
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
    row.pod ??
    row.binding ??
    row.image ??
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

/** Namespace-qualified id used by k8s state events (`resource_id`). */
export function resourceLookupId(item: InventoryResourceItem, row: ResourceRow): string | null {
  if (typeof row.pod === "string" && row.pod) return row.pod;
  if (typeof row.binding === "string" && row.binding) return row.binding;
  const name = row.name;
  if (typeof name !== "string" || !name) return null;
  const ns = typeof row.namespace === "string" ? row.namespace : "";
  return ns ? `${ns}/${name}` : name;
}

export function resourceDetailTitle(item: InventoryResourceItem, row: ResourceRow): string {
  const id = resourceLookupId(item, row) ?? resourcePrimaryId(item, row);
  return `${item.label}: ${id}`;
}

/** Inventory item ids whose rows map to a full object in the event store. */
export const K8S_STATE_EVENT_ITEMS = new Set([
  "k8s_pods",
  "k8s_nodes",
  "k8s_namespaces",
  "k8s_serviceaccounts",
  "k8s_secrets",
  "k8s_deployments",
  "k8s_daemonsets",
  "k8s_statefulsets",
  "k8s_jobs",
  "k8s_cronjobs",
  "k8s_pvs",
  "k8s_networkpolicies",
  "k8s_crds",
  "k8s_mutating_webhooks",
  "k8s_validating_webhooks",
  "k8s_roles",
  "k8s_clusterroles",
  "k8s_rolebindings",
  "k8s_clusterrolebindings",
  "k8s_suspicious_pods",
  "k8s_dangerous_bindings",
  "k8s_anonymous_bindings",
]);

export function columnsForResource(itemId: string): ResourceColumn[] {
  return (
    RESOURCE_COLUMNS[itemId] ?? [
      col("name", "Name", (r) => resourcePrimaryId({ id: itemId } as InventoryResourceItem, r)),
    ]
  );
}
