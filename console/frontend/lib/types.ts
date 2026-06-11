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
  harbor_source: string;
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
  harbor_source: FacetValue[];
  event_severity: FacetValue[];
  event_action: FacetValue[];
  user_name: FacetValue[];
  source_ip: FacetValue[];
  cloud_region: FacetValue[];
  cloud_service: FacetValue[];
  ua_category: FacetValue[];
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
  totals: { flows: number; bytes: number; rejects: number };
  top_talkers: { dest_ip: string; bytes: number; flows: number }[];
  rejected: { source_ip: string; dest_ip: string; dest_port: number; count: number }[];
}
