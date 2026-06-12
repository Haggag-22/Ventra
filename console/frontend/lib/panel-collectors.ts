// Maps each investigation panel to the Ventra collectors that feed it.

import { catalogItemForId, type CatalogItem, type Cloud } from "./catalog";

export type PanelId =
  | "overview"
  | "cloudtrail"
  | "findings"
  | "identity"
  | "network"
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
  overview: {
    blurb: "Roll-up metrics from baseline sources in this case.",
    collectors: [
      { id: "account" },
      { id: "cloudtrail" },
      { id: "iam" },
      { id: "sts" },
      { id: "vpc_flow" },
      { id: "guardduty" },
      { id: "waf" },
    ],
  },
  cloudtrail: {
    blurb: "API and control-plane activity across regions.",
    collectors: [{ id: "cloudtrail" }],
  },
  findings: {
    blurb: "Threat detections and compliance findings normalized to one view.",
    collectors: [
      { id: "guardduty" },
      { id: "securityhub" },
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
    blurb: "Flow logs and edge traffic for exfiltration and lateral movement.",
    collectors: [
      { id: "vpc_flow", note: "VPC flow records" },
      { id: "waf", note: "web ACL configs and sampled requests" },
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

export function catalogItem(cloud: Cloud, id: string): CatalogItem | undefined {
  return catalogItemForId(cloud, id);
}
