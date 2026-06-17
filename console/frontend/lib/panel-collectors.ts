// Maps each investigation panel to the Ventra collectors that feed it.

import { catalogItemForId, type CatalogItem, type Cloud } from "./catalog";

export type PanelId =
  | "cloudtrail"
  | "findings"
  | "identity"
  | "network"
  | "web"
  | "data-access"
  | "collection"
  | "resources";

export interface PanelCollectorRef {
  id: string;
  note?: string;
}

export interface PanelCollectorDef {
  blurb: string;
  collectors: PanelCollectorRef[];
}

export const PANEL_COLLECTORS: Record<PanelId, PanelCollectorDef> = {
  cloudtrail: {
    blurb: "API and control-plane activity across regions.",
    collectors: [{ id: "cloudtrail" }],
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
  "data-access": {
    blurb: "Object-level access — who read or wrote which S3 object, from where.",
    collectors: [
      { id: "s3_access", note: "S3 server access logs" },
      { id: "cloudtrail", note: "S3 object-level (data) events" },
    ],
  },
  collection: {
    blurb: "Log sources from the IR cheat sheet — what ran, what was missing, and why.",
    collectors: [],
  },
  resources: {
    blurb: "Resources",
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
    ],
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
    ],
  },
  web: {
    blurb: "Edge requests, WAF verdicts, and DNS (L7) — what was requested, by whom, with what result.",
    collectors: [
      { id: "app_gateway", note: "Application Gateway access + WAF" },
      { id: "front_door", note: "Front Door access + WAF" },
      { id: "dns", note: "DNS query logs" },
    ],
  },
  "data-access": {
    blurb: "Object-level and secret access — storage blobs, Key Vault operations.",
    collectors: [
      { id: "storage_access", note: "storage read/write/delete" },
      { id: "key_vault", note: "Key Vault audit events" },
      { id: "aks_audit", note: "Kubernetes API audit (cloud-side)" },
    ],
  },
  collection: {
    blurb: "Log sources from the IR cheat sheet — what ran, what was missing, and why.",
    collectors: [],
  },
  resources: {
    blurb: "Resources",
    collectors: [
      { id: "subscription", note: "tenant + subscription context" },
      { id: "resource_graph", note: "ARM inventory snapshot" },
    ],
  },
};

export function panelCollectors(cloud: Cloud): Record<PanelId, PanelCollectorDef> {
  if (cloud === "azure") return PANEL_COLLECTORS_AZURE;
  return PANEL_COLLECTORS;
}

export function catalogItem(cloud: Cloud, id: string): CatalogItem | undefined {
  return catalogItemForId(cloud, id);
}
