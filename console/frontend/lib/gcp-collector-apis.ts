/** Runtime Google Cloud APIs each Ventra GCP collector calls (default logging_api backend). */

export type GcpCollectorApiInfo = {
  /** APIs invoked by the collector at collection time. */
  calls: string[];
  /** Log names / resource types as shown in Cloud Logging Log Explorer. */
  logSource?: string[];
};

const LOG = "Cloud Logging API";
const CRM = "Cloud Resource Manager API";
const IAM = "Identity and Access Management API";
const COMPUTE = "Compute Engine API";
const GKE = "Kubernetes Engine API";
const SCC = "Security Command Center API";

export const GCP_COLLECTOR_APIS: Record<string, GcpCollectorApiInfo> = {
  project: { calls: [CRM] },
  iam_policy: { calls: [CRM, IAM] },
  cloud_audit_admin: {
    calls: [LOG],
    logSource: ["cloudaudit.googleapis.com/activity"],
  },
  cloud_audit_system: {
    calls: [LOG],
    logSource: ["cloudaudit.googleapis.com/system_event"],
  },
  cloud_audit_data: {
    calls: [LOG],
    logSource: ["cloudaudit.googleapis.com/data_access"],
  },
  logging_posture: { calls: [COMPUTE, LOG] },
  login_events: {
    calls: [LOG],
    logSource: ["cloudaudit.googleapis.com/data_access"],
  },
  vpc_flow: {
    calls: [LOG],
    logSource: ["compute.googleapis.com/vpc_flows"],
  },
  firewall_logs: {
    calls: [LOG],
    logSource: ["compute.googleapis.com/firewall"],
  },
  cloud_nat: {
    calls: [LOG],
    logSource: ["nat_gateway", "compute.googleapis.com/nat_flows"],
  },
  network_posture: { calls: [COMPUTE] },
  load_balancer: {
    calls: [LOG],
    logSource: ["compute.googleapis.com/requests", "loadbalancing.googleapis.com/requests"],
  },
  cloud_cdn: {
    calls: [LOG],
    logSource: ["http_load_balancer"],
  },
  api_gateway: {
    calls: [LOG],
    logSource: ["apigateway.googleapis.com/gateway"],
  },
  cloud_dns: {
    calls: [LOG],
    logSource: ["dns_query"],
  },
  cloud_armor: {
    calls: [COMPUTE, LOG],
    logSource: ["compute.googleapis.com/requests", "loadbalancing.googleapis.com/requests"],
  },
  vm_logs: {
    calls: [LOG],
    logSource: ["gce_instance"],
  },
  gce: { calls: [COMPUTE] },
  cloud_functions: {
    calls: [LOG],
    logSource: ["cloudfunctions.googleapis.com/cloud-functions"],
  },
  gke_audit: {
    calls: [GKE, LOG],
    logSource: ["k8s_cluster"],
  },
  storage_access: {
    calls: [LOG],
    logSource: ["storage.googleapis.com/requests"],
  },
  bigquery_audit: {
    calls: [LOG],
    logSource: ["cloudaudit.googleapis.com/data_access", "bigquery_resource"],
  },
  cloud_sql: {
    calls: [LOG],
    logSource: ["cloudsql_database"],
  },
  secret_manager: {
    calls: [LOG],
    logSource: ["cloudaudit.googleapis.com/data_access"],
  },
  scc_findings: { calls: [SCC] },
  cloud_monitoring: {
    calls: [LOG],
    logSource: ["monitoring.googleapis.com", "alerting.googleapis.com"],
  },
};

export function gcpCollectorApiInfo(collector: string): GcpCollectorApiInfo | null {
  return GCP_COLLECTOR_APIS[collector] ?? null;
}
