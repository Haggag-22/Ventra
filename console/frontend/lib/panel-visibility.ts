/** Which investigation panels a case's platform actually has evidence for. */

import type { Cloud } from "./catalog";

/**
 * Panels hidden per platform because no collector on that platform feeds them.
 *
 * CloudWatch Logs is AWS-only. On-prem Kubernetes has no cloud flow logs, CDN, load
 * balancer or DNS service, so Network Activity and Web & DNS would render permanently
 * empty — the evidence for lateral movement in a cluster is the CNI plugin (out of scope
 * for this pass), and ingress access logs are the workload's own pod logs.
 */
const HIDDEN_PANELS: Record<Cloud, readonly string[]> = {
  aws: [],
  azure: ["cloudwatch"],
  gcp: ["cloudwatch"],
  kubernetes: ["cloudwatch", "network", "web"],
};

export function isPanelVisible(cloud: Cloud, href: string): boolean {
  return !(HIDDEN_PANELS[cloud] ?? []).includes(href);
}
