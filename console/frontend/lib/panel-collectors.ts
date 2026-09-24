// Maps each investigation panel to the Ventra collectors that feed it.

import { catalogItemForId, type CatalogItem, type Cloud } from "./catalog";

export type PanelId =
  | "cloudtrail"
  | "cloudwatch"
  | "findings"
  | "identity"
  | "network"
  | "web"
  | "kubernetes-audit"
  | "data-access"
  | "collection"
  | "resources";

/** CloudTrail sub-category a panel depends on (default: any collected category). */
export type CloudTrailAspect =
  | "data_events"
  | "management_events"
  | "insight_events"
  | "network_activity";

export interface PanelCollectorRef {
  id: string;
  /** Override catalog label in panel header chips (e.g. scoped CloudTrail category). */
  label?: string;
  note?: string;
  /** When set on a cloudtrail ref, panel coverage requires this event category. */
  cloudtrailAspect?: CloudTrailAspect;
  /** Consecutive refs sharing a group key render in one horizontal aspect box. */
  aspectGroup?: string;
}

/** Header + icon for grouped aspect chips (CloudTrail, Cloud Audit Logs, …). */
export const COLLECTOR_ASPECT_GROUPS: Record<
  string,
  { label: string; iconCollector: string; ariaPrefix: string }
> = {
  cloudtrail: { label: "CloudTrail", iconCollector: "cloudtrail", ariaPrefix: "CloudTrail" },
  cloud_audit: {
    label: "Cloud Audit Logs",
    iconCollector: "cloud_audit_admin",
    ariaPrefix: "Cloud Audit",
  },
};

export interface PanelCollectorDef {
  blurb: string;
  collectors: PanelCollectorRef[];
}

/** CloudTrail event categories shown as separate checkboxes on the CloudTrail panel. */
export const AWS_CLOUDTRAIL_ASPECTS: PanelCollectorRef[] = [
  { id: "cloudtrail", label: "Management", cloudtrailAspect: "management_events", aspectGroup: "cloudtrail" },
  { id: "cloudtrail", label: "Data Events", cloudtrailAspect: "data_events", aspectGroup: "cloudtrail" },
  { id: "cloudtrail", label: "Insights", cloudtrailAspect: "insight_events", aspectGroup: "cloudtrail" },
  { id: "cloudtrail", label: "Network Activity", cloudtrailAspect: "network_activity", aspectGroup: "cloudtrail" },
];

/** GCP Cloud Audit log types grouped on the Audit Log panel. */
export const GCP_CLOUD_AUDIT_ASPECTS: PanelCollectorRef[] = [
  { id: "cloud_audit_admin", label: "Admin Activity Audit Logs", aspectGroup: "cloud_audit" },
  { id: "cloud_audit_system", label: "System Event Audit Logs", aspectGroup: "cloud_audit" },
  { id: "cloud_audit_data", label: "Data Access Audit Logs", aspectGroup: "cloud_audit" },
];

export const PANEL_COLLECTORS: Record<PanelId, PanelCollectorDef> = {
  cloudtrail: {
    blurb: "API and control-plane activity across regions.",
    collectors: AWS_CLOUDTRAIL_ASPECTS,
  },
  cloudwatch: {
    blurb: "CloudWatch Logs events from selected log groups.",
    collectors: [{ id: "cloudwatch" }],
  },
  findings: {
    blurb: "Threat detections and compliance findings normalized to one view.",
    collectors: [
      { id: "guardduty" },
      { id: "securityhub" },
      { id: "inspector2", note: "vulnerability / reachability findings" },
      { id: "macie" },
      { id: "detective" },
      { id: "config" },
    ],
  },
  identity: {
    blurb: "IAM posture, credentials, and related key/secret inventory.",
    collectors: [
      { id: "iam", note: "users, roles, policies, credential report" },
      { id: "kms", note: "key inventory" },
      { id: "secrets", note: "secret metadata" },
    ],
  },
  network: {
    blurb: "VPC flow logs (L3/L4) for exfiltration volume and lateral movement.",
    collectors: [{ id: "vpc_flow", note: "VPC flow records" }],
  },
  web: {
    blurb: "Edge requests, WAF verdicts, and DNS (L7) — what was requested, by whom, with what result.",
    collectors: [
      { id: "elb_alb", note: "load-balancer access logs" },
      { id: "cloudfront", note: "CDN edge access logs" },
      { id: "waf", note: "web ACL sampled requests" },
      { id: "route53_resolver", note: "DNS query logs" },
    ],
  },
  "kubernetes-audit": {
    blurb: "Kubernetes API-server audit logs from managed clusters.",
    collectors: [{ id: "eks_audit" }],
  },
  "data-access": {
    blurb: "Object-level access — who read or wrote which S3 object, from where.",
    collectors: [
      { id: "s3_access", note: "S3 server access logs" },
      {
        id: "cloudtrail",
        label: "CloudTrail S3 Data Events",
        note: "S3 object-level (data) events only — not management, insight, or network activity",
        cloudtrailAspect: "data_events",
      },
    ],
  },
  collection: {
    blurb: "Log sources from the IR cheat sheet — what ran, what was missing, and why.",
    collectors: [],
  },
  resources: {
    blurb: "EC2, S3, Lambda inventory and related account resource posture.",
    collectors: [
      { id: "ec2" },
      { id: "s3" },
      { id: "lambda" },
      { id: "vpc_flow", note: "VPC and flow-log config" },
      { id: "waf" },
      { id: "kms" },
      { id: "secrets" },
      { id: "iam", note: "principal counts" },
    ],
  },
};

const PANEL_COLLECTORS_AZURE: Record<PanelId, PanelCollectorDef> = {
  cloudtrail: {
    blurb: "Control-plane activity across subscriptions and resources.",
    collectors: [
      { id: "activity_log" },
      { id: "entra_signin", note: "sign-in logs" },
      { id: "entra_audit", note: "directory audit" },
      { id: "oauth_consent", note: "standing OAuth grants" },
    ],
  },
  cloudwatch: {
    blurb: "CloudWatch Logs is an AWS investigation panel.",
    collectors: [],
  },
  findings: {
    blurb: "Microsoft Defender for Cloud alerts.",
    collectors: [{ id: "defender" }],
  },
  identity: {
    blurb: "Entra ID and Azure RBAC posture.",
    collectors: [
      { id: "entra_directory", note: "users, groups, apps, service principals" },
      { id: "rbac", note: "role definitions and assignments" },
    ],
  },
  network: {
    blurb: "VNet/NSG flow and firewall logs (L3/L4) for exfiltration and lateral movement.",
    collectors: [
      { id: "vnet_flow", note: "VNet flow records" },
      { id: "nsg_flow", note: "NSG flow records (legacy)" },
      { id: "azure_firewall", note: "firewall application/network rules" },
      { id: "log_analytics", note: "LA-routed firewall / flow diagnostics" },
    ],
  },
  web: {
    blurb: "Edge requests, WAF verdicts, and DNS (L7) — what was requested, by whom, with what result.",
    collectors: [
      { id: "app_gateway", note: "Application Gateway access + WAF" },
      { id: "front_door", note: "Front Door access + WAF" },
      { id: "dns", note: "DNS query logs" },
      { id: "log_analytics", note: "LA-routed App Gateway / Front Door / DNS" },
    ],
  },
  "kubernetes-audit": {
    blurb: "AKS kube-audit logs from cluster diagnostics.",
    collectors: [{ id: "aks_audit" }],
  },
  "data-access": {
    blurb: "Object-level and secret access — storage blobs, Key Vault operations.",
    collectors: [
      { id: "storage_access", note: "storage read/write/delete" },
      { id: "key_vault", note: "Key Vault audit events" },
      { id: "log_analytics", note: "LA-routed storage / Key Vault diagnostics" },
    ],
  },
  collection: {
    blurb: "Log sources from the IR cheat sheet — what ran, what was missing, and why.",
    collectors: [],
  },
  resources: {
    blurb: "Subscription context and ARM inventory from Resource Graph.",
    collectors: [
      { id: "subscription", note: "tenant + subscription context" },
      { id: "resource_graph", note: "ARM inventory snapshot" },
    ],
  },
};

const PANEL_COLLECTORS_GCP: Record<PanelId, PanelCollectorDef> = {
  cloudtrail: {
    blurb: "Cloud Audit Logs — admin activity, system events, and data access across projects.",
    collectors: [
      ...GCP_CLOUD_AUDIT_ASPECTS,
      { id: "login_events", note: "Google Cloud console sign-ins" },
    ],
  },
  cloudwatch: {
    blurb: "CloudWatch Logs is an AWS investigation panel.",
    collectors: [],
  },
  findings: {
    blurb: "Security Command Center findings and Cloud Monitoring alert notifications.",
    collectors: [
      { id: "scc_findings", note: "SCC threat and misconfiguration findings" },
      { id: "cloud_monitoring", note: "monitoring alert incidents" },
    ],
  },
  identity: {
    blurb: "IAM policy bindings and login audit events.",
    collectors: [
      { id: "iam_policy", note: "IAM snapshot per project" },
      { id: "login_events", note: "Google Cloud console sign-ins" },
    ],
  },
  network: {
    blurb: "VPC flow, firewall, and NAT logs plus network posture (rules, topology, mirroring).",
    collectors: [
      { id: "vpc_flow", note: "VPC / subnets" },
      { id: "firewall_logs", note: "VPC firewall" },
      { id: "cloud_nat", note: "Cloud NAT" },
      { id: "network_posture", note: "firewall rules, VPC topology, packet mirroring" },
    ],
  },
  web: {
    blurb: "Edge requests, WAF verdicts, and DNS (L7) — what was requested, by whom, with what result.",
    collectors: [
      { id: "load_balancer", note: "Cloud Load Balancing Logs" },
      { id: "cloud_cdn", note: "Cloud CDN cache request logs" },
      { id: "api_gateway", note: "API Gateway request logs" },
      { id: "cloud_dns", note: "Cloud DNS" },
      { id: "cloud_armor", note: "Cloud Armor WAF" },
    ],
  },
  "kubernetes-audit": {
    blurb: "GKE Kubernetes API-server audit logs from managed clusters.",
    collectors: [{ id: "gke_audit" }],
  },
  "data-access": {
    blurb: "Cloud Storage, BigQuery, Cloud SQL, and Secret Manager access — who read or wrote which resource, from where.",
    collectors: [
      { id: "storage_access", note: "GCS bucket access logs" },
      { id: "bigquery_audit", note: "BigQuery data access audit" },
      { id: "cloud_sql", note: "Cloud SQL query and connection logs" },
      { id: "secret_manager", note: "Secret Manager access audit" },
      {
        id: "cloud_audit_data",
        label: "Data Access Audit Logs",
        note: "data access audit trail — not admin or system event logs",
      },
    ],
  },
  collection: {
    blurb: "Log sources from the GCP IR cheat sheet — what ran, what was missing, and why.",
    collectors: [{ id: "logging_posture", note: "flow logs, firewall logging, audit sinks" }],
  },
  resources: {
    blurb: "Project context, GCE inventory, and related compute workload logs.",
    collectors: [
      { id: "project", note: "project + organization context" },
      { id: "gce", note: "GCE instances, disks, snapshots, NICs" },
      { id: "vm_logs", note: "Compute Engine VM logs" },
      { id: "cloud_functions", note: "Cloud Functions execution logs" },
    ],
  },
};

const PANEL_COLLECTORS_KUBERNETES: Record<PanelId, PanelCollectorDef> = {
  cloudtrail: {
    blurb:
      "The cluster timeline: the API-server audit log (who did what), the cluster datastore " +
      "posture, and the object state each action produced.",
    collectors: [
      { id: "k8s_apiserver_audit", note: "who did what — exec, secret reads, RBAC changes" },
      { id: "k8s_events", note: "perishable; garbage-collected after --event-ttl (1h default)" },
      { id: "k8s_etcd", note: "datastore journal + TLS and at-rest posture" },
    ],
  },
  cloudwatch: {
    blurb: "CloudWatch Logs is an AWS investigation panel.",
    collectors: [],
  },
  findings: {
    blurb:
      "Posture findings the collectors raise — a missing audit log, a weak audit policy, or " +
      "etcd / datastore exposure.",
    collectors: [
      { id: "k8s_audit_posture", note: "is audit logging on, and is the policy useful" },
      { id: "k8s_etcd", note: "client cert auth, listen addresses, encryption at rest" },
    ],
  },
  identity: {
    blurb:
      "RBAC roles and bindings with escalation analysis, plus ServiceAccounts and their " +
      "token automount settings.",
    collectors: [
      { id: "k8s_rbac", note: "roles, bindings, escalation paths, anonymous subjects" },
      { id: "k8s_cluster_state", note: "ServiceAccounts, Secret metadata, token automount" },
    ],
  },
  network: {
    blurb: "NetworkPolicies and CNI plugin flow logs.",
    collectors: [
      { id: "k8s_cni_logs", note: "Calico / Cilium / Flannel logs and flows" },
      { id: "k8s_cluster_state", note: "NetworkPolicy objects" },
    ],
  },
  web: {
    blurb: "Ingress request logs come from the ingress controller's container logs on the node.",
    collectors: [{ id: "k8s_container_logs", note: "ingress controller stdout/stderr under /var/log/pods" }],
  },
  "kubernetes-audit": {
    blurb:
      "The API-server audit log read from the control-plane node — the only record of " +
      "pods/exec, secret reads, and RBAC changes. On-prem this is a file on disk, not a " +
      "cloud log stream.",
    collectors: [
      { id: "k8s_apiserver_audit" },
      { id: "k8s_audit_posture", note: "whether the log exists at all, and what it covers" },
    ],
  },
  "data-access": {
    blurb:
      "In a cluster, data access means Secret reads — recorded only in the API-server audit " +
      "log — plus etcd, which holds every Secret in plaintext without encryption at rest.",
    collectors: [
      { id: "k8s_apiserver_audit", note: "get / list on secrets and configmaps" },
      { id: "k8s_etcd", note: "etcd access posture and at-rest encryption" },
    ],
  },
  collection: {
    blurb:
      "Evidence sources for an on-prem cluster, by plane: the API server (kubeconfig) and " +
      "the nodes (privileged DaemonSet or Job) — what ran, what was missing, and why.",
    collectors: [
      { id: "k8s_audit_posture", note: "the most common Kubernetes IR gap: no audit log" },
    ],
  },
  resources: {
    blurb:
      "Cluster object inventory: workloads, identity, storage and admission objects across " +
      "every namespace, with the container-escape-shaped pods flagged.",
    collectors: [
      { id: "k8s_cluster_state", note: "all-namespace inventory + suspicious pods" },
      { id: "k8s_container_logs", note: "container logs from the node, incl. rotated" },
      { id: "k8s_kubelet_logs", note: "pod admission, image pulls, container lifecycle" },
      { id: "k8s_runtime_logs", note: "CRI journal (containerd / CRI-O) + live crictl state" },
    ],
  },
};

export function panelCollectors(cloud: Cloud): Record<PanelId, PanelCollectorDef> {
  if (cloud === "azure") return PANEL_COLLECTORS_AZURE;
  if (cloud === "gcp") return PANEL_COLLECTORS_GCP;
  if (cloud === "kubernetes") return PANEL_COLLECTORS_KUBERNETES;
  return PANEL_COLLECTORS;
}

export function catalogItem(cloud: Cloud, id: string): CatalogItem | undefined {
  return catalogItemForId(cloud, id);
}
