// Shared types mirroring the backend's responses (the unified event schema, summaries, etc.).

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Integrity = "green" | "amber" | "red" | "unknown";
export type Outcome = "success" | "failure" | "unknown";

export interface UnifiedEvent {
  timestamp: string;
  event_kind: string;
  event_category: string[];
  event_action: string;
  event_outcome: Outcome;
  event_severity: Severity;
  event_provider: string;
  cloud_provider: string;
  cloud_account: string;
  cloud_region: string;
  cloud_service: string;
  user_name: string;
  user_id: string;
  user_arn: string;
  user_type: string;
  source_ip: string;
  source_country: string;
  source_asn: string;
  dest_ip: string;
  dest_port: number | null;
  dest_bytes: number | null;
  resource_type: string;
  resource_id: string;
  resource_arn: string;
  ua_original: string;
  ua_category: string;
  related_ip: string[];
  related_user: string[];
  related_resource: string[];
  message: string;
  case_id: string;
  ventra_source: string;
  raw: Record<string, unknown>;
}

export interface EventsResponse {
  total: number;
  count: number;
  offset: number;
  events: UnifiedEvent[];
}

export interface FacetValue {
  value: string;
  count: number;
}
export interface Facets {
  ventra_source: FacetValue[];
  event_severity: FacetValue[];
  event_action: FacetValue[];
  event_outcome: FacetValue[];
  user_name: FacetValue[];
  source_ip: FacetValue[];
  dest_ip: FacetValue[];
  dest_port: FacetValue[];
  cloud_region: FacetValue[];
  cloud_service: FacetValue[];
  ua_category: FacetValue[];
  trail_category: FacetValue[];
  finding_class: FacetValue[];
  resource_id: FacetValue[];
  http_status: FacetValue[];
  principal: FacetValue[];
}

export interface CaseSummary {
  case_id: string;
  account_id: string;
  account_alias: string;
  cloud: string;
  regions: string[];
  operator: { principal_arn?: string; source_ip?: string };
  profile: { name?: string; overrides?: string[] };
  time_window: { since?: string | null; until?: string | null; mode?: string };
  started_at: string;
  completed_at: string;
  integrity: Integrity;
  signature_method: string;
  totals: {
    events: number;
    principals: number;
    source_ips: number;
    sensitive_actions: number;
    failures: number;
  };
  event_span: { first: string | null; last: string | null };
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_source: Record<string, number>;
  top_principals: [string, number][];
  top_source_ips: [string, number][];
  collection: { collected: string[]; gaps: { name: string; reason: string; detail: string }[] };
  sources_loaded?: string[];
  inventory_loaded?: string[];
}

export interface IntegrityReport {
  case_id: string;
  overall: Integrity;
  signature_method: string;
  signature_valid: boolean;
  notes: string[];
  missing: string[];
  checks: {
    name: string;
    arcname: string;
    expected_sha256: string;
    actual_sha256: string;
    matched: boolean;
    status: string;
  }[];
}

export interface TimelinePoint {
  t: string;
  severity: Severity;
  source: string;
}
export interface TimelineResponse {
  min: string | null;
  max: string | null;
  points: TimelinePoint[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: "principal" | "role";
}
export interface GraphEdge {
  source: string;
  target: string;
  weight: number;
  ip: string;
}
export interface IdentityResponse {
  iam: Record<string, any> | null;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
}

export interface NetworkResponse {
  totals: {
    flows: number;
    accepted: number;
    rejects: number;
    bytes: number;
    public_bytes: number;
    external_dests: number;
    sources: number;
  };
  egress_public: { dest_ip: string; bytes: number; flows: number; ports: number }[];
  top_talkers: { source_ip: string; bytes: number; flows: number }[];
  top_ports: { port: number; flows: number; bytes: number; rejected: number }[];
  rejected: { source_ip: string; dest_ip: string; dest_port: number; count: number }[];
  protocols: { protocol: string; count: number }[];
}

export interface WebDnsResponse {
  edge: {
    totals: { requests: number; clients: number; failures: number };
    by_source: { source: string; count: number }[];
    top_clients: {
      source_ip: string;
      requests: number;
      failures: number;
      last_seen: string;
    }[];
    methods: { method: string; count: number }[];
    user_agents: { ua: string; count: number }[];
    top_resources: {
      source: string;
      resource_id: string;
      count: number;
      failures: number;
    }[];
    status_classes: { cls: string; count: number }[];
    top_paths: { target: string; count?: number; failures?: number }[];
  };
  waf: {
    totals: { sampled: number; blocked: number; clients: number };
    actions: { action: string; count: number }[];
    top_ips: { source_ip: string; country: string; count: number; blocked: number }[];
  };
  dns: {
    totals: { queries: number; domains: number; failures: number };
    top_domains: { domain: string; count: number; failures: number; answer: string }[];
    qtypes: { qtype: string; count: number }[];
  };
}

export interface DataAccessResponse {
  totals: {
    events: number;
    objects: number;
    principals: number;
    failures: number;
    bytes_out: number;
    deletes: number;
    writes: number;
  };
  by_source: { source: string; count: number }[];
  operations: { op: string; count: number }[];
  top_objects: {
    resource_id: string;
    count: number;
    failures: number;
    ips: number;
    bytes: number;
  }[];
  top_principals: { principal: string; count: number; failures: number; bytes: number }[];
  top_ips: {
    source_ip: string;
    count: number;
    failures: number;
    bytes: number;
  }[];
}

export interface CloudTrailTrailSummary {
  name: string;
  arn: string;
  home_region: string;
  s3_bucket: string;
  s3_key_prefix: string;
  is_logging: boolean;
  is_multi_region: boolean;
  is_organization: boolean;
  log_file_validation: boolean;
  management_events_configured?: boolean;
  data_events_configured?: boolean;
  network_activity_configured?: boolean;
  insight_events_configured?: boolean;
}

export interface CloudTrailBucketSummary {
  bucket: string;
  trail_arns: string[];
  events: {
    management?: number;
    data?: number;
    insight?: number;
    network_activity?: number;
    total: number;
  };
  objects_read?: number;
  truncated?: boolean;
}

export interface CloudTrailLogValidationTrail {
  trail_arn: string;
  trail_name: string;
  status: "valid" | "invalid" | "skipped" | "error";
  skip_reason?: string;
  digest_valid?: number;
  digest_total?: number;
  digest_invalid?: number;
  log_valid?: number;
  log_total?: number;
  log_invalid?: number;
  invalid_details?: string[];
}

export interface CloudTrailLogValidation {
  window?: Record<string, unknown>;
  trails?: CloudTrailLogValidationTrail[];
  any_invalid?: boolean;
  any_validated?: boolean;
}

export interface CloudTrailManagementTrail {
  trail_name: string;
  trail_arn: string;
  bucket: string;
  status: "collected" | "denied" | "empty";
  records: number;
  objects_read?: number;
  reason?: string;
}

export interface CloudTrailManagementCollection {
  mode: "trails" | "event_history";
  trails: CloudTrailManagementTrail[];
  trails_total: number;
  trails_collected: number;
  buckets: string[];
  records: number;
  fallback_reason?: string;
}

export interface CloudTrailCollection {
  trail_count: number;
  trails: CloudTrailTrailSummary[];
  management_source?: "s3_logs" | "lookup_events" | "";
  management_collection?: CloudTrailManagementCollection;
  event_coverage: Record<string, unknown>;
  s3_collection: Record<string, unknown>;
  log_validation?: CloudTrailLogValidation;
  events: {
    lookup_api: { management: number; insight: number; total: number };
    s3: {
      total: number;
      management?: number;
      data?: number;
      insight?: number;
      network_activity?: number;
      by_bucket: CloudTrailBucketSummary[];
    };
  };
  meta: Record<string, unknown>;
}

export interface InventoryResourceItem {
  id: string;
  label: string;
  source: string;
  key: string;
  count: number | null;
  collected: boolean;
}

export interface InventorySummary {
  sources: string[];
  categories: { name: string; items: InventoryResourceItem[] }[];
  total_resources: number;
}

// ---- Acquire (artifact library + kit builder) ------------------------------------------

export interface Artifact {
  name: string;
  collector: string;
  cloud: string;
  category: string;
  description: string;
  version: string;
  severity: string;
  estimated_volume: string;
  required_actions: string[];
  aliases?: string[];
  parameters?: Record<string, unknown>;
  sources?: { type: string; format?: string }[];
  implicit?: boolean;
  selectable?: boolean;
}

export interface ArtifactPack {
  pack: string;
  name: string;
  cloud: string;
  description: string;
  version: string;
  artifacts: string[];
}
