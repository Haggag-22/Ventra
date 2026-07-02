"""GCP log collection backend — how logging collectors read records.

Configured in ``acquisition.yaml`` as ``gcp_log_backend`` and chosen in the Acquire UI.
Ventra is read-only: ``setup_required`` means the *client admin* creates sinks/export
before collection; the collector never creates datasets, buckets, or sinks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Date-sharded export tables end in _YYYYMMDD; partitioned tables use the bare base name.
_TABLE_DATE_SHARD = re.compile(r"^(.*_)\d{8}$")

# Collectors that pull rows via Cloud Logging API, BigQuery export, or GCS archive.
GCP_LOGGING_COLLECTOR_IDS: frozenset[str] = frozenset(
    {
        "cloud_audit_admin",
        "cloud_audit_system",
        "cloud_audit_data",
        "login_events",
        "vpc_flow",
        "firewall_logs",
        "cloud_nat",
        "load_balancer",
        "cloud_cdn",
        "api_gateway",
        "cloud_dns",
        "vm_logs",
        "cloud_functions",
        "storage_access",
        "bigquery_audit",
        "cloud_sql",
        "secret_manager",
        "cloud_monitoring",
        # Also use list_log_entries directly (not GcpLoggingCollector base):
        "cloud_armor",
        "gke_audit",
    }
)

_EXTRA_IAM_BY_MODE: dict[str, frozenset[str]] = {
    "logging_api": frozenset({"logging.logEntries.list"}),
    "bigquery": frozenset(
        {
            "bigquery.jobs.create",
            "bigquery.datasets.get",
            "bigquery.tables.get",
            "bigquery.tables.getData",
            "bigquery.tables.list",
        }
    ),
    "gcs": frozenset(
        {
            "storage.buckets.get",
            "storage.objects.get",
            "storage.objects.list",
        }
    ),
}

# Logging API permissions omitted when Export / Archive backends are selected.
_LOGGING_API_ONLY: frozenset[str] = frozenset(
    {
        "logging.logEntries.list",
        "logging.logs.list",
    }
)


# Default BQ table when a single sink writes all log types to one table.
_BQ_DEFAULT_TABLE_FALLBACK = "_Default"

# BQ table candidates per collector, most specific first (one logName = one table; sinks
# sanitize the logName: dots/slashes/dashes → underscores). Collectors listed in
# ``_COLLECTOR_BQ_UNION`` read EVERY listed table (fan-out/union); everyone else stops at the
# first table that yields rows.
_COLLECTOR_BQ_TABLE_HINTS: dict[str, tuple[str, ...]] = {
    "cloud_audit_admin": ("cloudaudit_googleapis_com_activity",),
    "cloud_audit_system": ("cloudaudit_googleapis_com_system_event",),
    "cloud_audit_data": ("cloudaudit_googleapis_com_data_access",),
    # serviceName views over the shared audit streams — same tables as their broad stream.
    "login_events": ("cloudaudit_googleapis_com_data_access",),
    "storage_access": ("cloudaudit_googleapis_com_data_access",),
    "bigquery_audit": ("cloudaudit_googleapis_com_data_access",),
    "secret_manager": ("cloudaudit_googleapis_com_data_access",),
    # VPC Flow Logs = union of the compute and networkmanagement streams.
    "vpc_flow": (
        "compute_googleapis_com_vpc_flows",
        "networkmanagement_googleapis_com_vpc_flows",
    ),
    "firewall_logs": ("compute_googleapis_com_firewall",),
    "cloud_nat": ("compute_googleapis_com_nat_flows",),
    # LB access logs land in `requests`; older sinks used the full sanitized logName.
    "load_balancer": ("requests", "compute_googleapis_com_requests"),
    "cloud_cdn": ("requests", "compute_googleapis_com_requests"),
    "cloud_armor": ("requests", "compute_googleapis_com_requests"),
    "api_gateway": ("apigateway_googleapis_com_requests",),
    "cloud_dns": ("dns_googleapis_com_dns_queries",),
    # Agent logs fan out over per-stream tables named after the agent logName.
    "vm_logs": (
        "syslog",
        "auth",
        "authlog",
        "secure",
        "messages",
        "winevt_raw",
        "windows_event_log",
        "google_metadata_script_runner",
    ),
    "gke_audit": ("container_googleapis_com_apiserver",),
    # cloudsql_googleapis_com_* fans out per engine stream; the wildcard form reads them all.
    "cloud_sql": ("cloudsql_googleapis_com",),
    "cloud_monitoring": ("monitoring_googleapis_com_activity",),
    "cloud_functions": ("cloudfunctions_googleapis_com_cloud_functions",),
}

# Collectors whose table list is a union/fan-out: read all tables, not first-match.
# vpc_flow = compute + networkmanagement streams; vm_logs = per-agent-stream tables;
# cloud_sql = per-engine streams (postgres.log, mysql.err, …) under one sanitized prefix.
_COLLECTOR_BQ_UNION: frozenset[str] = frozenset({"vpc_flow", "vm_logs", "cloud_sql"})

# GCS log archive objects mirror the raw logName as a folder path:
# <bucket>/<sink prefix>/<logName>/YYYY/MM/DD/*.json. Same first-match vs union semantics
# as the BQ hints (alternative names for one log vs fan-out over distinct streams).
_COLLECTOR_GCS_PREFIX_HINTS: dict[str, tuple[str, ...]] = {
    "cloud_audit_admin": ("cloudaudit.googleapis.com/activity/",),
    "cloud_audit_system": ("cloudaudit.googleapis.com/system_event/",),
    "cloud_audit_data": ("cloudaudit.googleapis.com/data_access/",),
    "login_events": ("cloudaudit.googleapis.com/data_access/",),
    "storage_access": ("cloudaudit.googleapis.com/data_access/",),
    "bigquery_audit": ("cloudaudit.googleapis.com/data_access/",),
    "secret_manager": ("cloudaudit.googleapis.com/data_access/",),
    "vpc_flow": (
        "compute.googleapis.com/vpc_flows/",
        "networkmanagement.googleapis.com/vpc_flows/",
    ),
    "firewall_logs": ("compute.googleapis.com/firewall/",),
    "cloud_nat": ("compute.googleapis.com/nat_flows/",),
    "load_balancer": ("requests/", "compute.googleapis.com/requests/"),
    "cloud_cdn": ("requests/", "compute.googleapis.com/requests/"),
    "cloud_armor": ("requests/", "compute.googleapis.com/requests/"),
    "api_gateway": ("apigateway.googleapis.com/requests/",),
    "cloud_dns": ("dns.googleapis.com/dns_queries/",),
    "vm_logs": (
        "syslog/",
        "auth/",
        "authlog/",
        "secure/",
        "messages/",
        "winevt.raw/",
        "windows_event_log/",
        "google_metadata_script_runner/",
    ),
    "gke_audit": ("container.googleapis.com/apiserver/",),
    "cloud_sql": ("cloudsql.googleapis.com/",),
    "cloud_monitoring": ("monitoring.googleapis.com/",),
    "cloud_functions": ("cloudfunctions.googleapis.com/cloud-functions/",),
}

# serviceName / field-filter views over a broad stream's shared table. When the broad stream is
# also selected, the view must NOT be collected again — it is derived from the broad stream.
GCP_SUBSET_OF: dict[str, str] = {
    "login_events": "cloud_audit_data",
    "storage_access": "cloud_audit_data",
    "bigquery_audit": "cloud_audit_data",
    "secret_manager": "cloud_audit_data",
    "cloud_cdn": "load_balancer",
    "cloud_armor": "load_balancer",
}

# Broad-stream Cloud Logging filter per shared-table group, used to fill a shared read once.
# The LB request log is named bare `requests` on modern sinks (older: compute.googleapis.com/
# requests), so resource.type is the discriminator and logName only needs the common fragment.
_SHARED_GROUP_FILTERS: dict[str, str] = {
    "cloud_audit_data": 'logName:"cloudaudit.googleapis.com%2Fdata_access"',
    "load_balancer": 'resource.type="http_load_balancer" AND logName:"requests"',
}


def deduplicate_gcp_selection(selected: list[str]) -> dict[str, str]:
    """Return ``{subset_collector: broad_collector}`` for subsets already covered by a
    selected broad stream. Those subsets must be skipped (collected once via the broad
    stream), never queried a second time."""
    chosen = set(selected)
    return {
        subset: broad
        for subset, broad in GCP_SUBSET_OF.items()
        if subset in chosen and broad in chosen
    }


def shared_log_read_groups(run_collectors: list[str]) -> dict[str, dict[str, Any]]:
    """Shared-table read plan for export backends (BigQuery / GCS).

    When two or more subset views of the same shared table are collected in one run (and the
    broad stream itself is not), the table is read ONCE with the broad filter and each view is
    filtered from that single read in memory, instead of re-querying per service.
    Returns ``{collector: {"group": broad_id, "log_filter": broad_filter, "tables": [...]}}``.
    """
    members: dict[str, list[str]] = {}
    for name in run_collectors:
        broad = GCP_SUBSET_OF.get(name)
        if broad is not None and broad not in run_collectors:
            members.setdefault(broad, []).append(name)
    out: dict[str, dict[str, Any]] = {}
    for broad, subs in members.items():
        if len(subs) < 2:
            continue
        for name in subs:
            out[name] = {
                "group": broad,
                "log_filter": _SHARED_GROUP_FILTERS[broad],
                "tables": list(_COLLECTOR_BQ_TABLE_HINTS.get(broad, ())),
            }
    return out


def bigquery_reads_all_tables(collector: str) -> bool:
    """True when the collector is a union/fan-out over every listed table."""
    return collector in _COLLECTOR_BQ_UNION


def log_name_to_bigquery_table_id(log_name: str) -> str:
    """GCP log sinks often name BQ tables from the log name (dots/slashes → underscores)."""
    return log_name.replace(".", "_").replace("/", "_").replace("-", "_")


def bigquery_table_hints(collector: str) -> tuple[str, ...]:
    """Export table base names for a collector (authoritative mapping, no ``_Default``)."""
    return _COLLECTOR_BQ_TABLE_HINTS.get(collector, ())


def gcs_prefix_hints(collector: str) -> tuple[str, ...]:
    """GCS archive object prefixes for a collector (relative to the sink prefix)."""
    return _COLLECTOR_GCS_PREFIX_HINTS.get(collector, ())


def known_bigquery_table_bases() -> dict[str, str]:
    """``{table_base: collector}`` reverse map over every hinted export table."""
    out: dict[str, str] = {}
    for collector, tables in _COLLECTOR_BQ_TABLE_HINTS.items():
        for table in tables:
            out.setdefault(table, collector)
    return out


def classify_bigquery_table(table_id: str) -> str:
    """Classify a discovered export table as ``known`` / ``noise`` / ``unknown``.

    ``noise`` covers BigQuery bookkeeping and the ``_Default``/``_AllLogs`` catch-alls;
    ``known`` means the (date-shard-stripped) name reverse-maps to a collector.
    """
    base = strip_bigquery_date_shard(table_id)
    if base.startswith("_"):
        return "noise"
    for known in known_bigquery_table_bases():
        if base == known or base.startswith(f"{known}_"):
            return "known"
    return "unknown"


def strip_bigquery_date_shard(table_id: str) -> str:
    """Return the table base name with any ``_YYYYMMDD`` date-shard suffix removed."""
    match = _TABLE_DATE_SHARD.match(table_id)
    return match.group(1).rstrip("_") if match else table_id


def bigquery_table_is_date_sharded(table_id: str) -> bool:
    return _TABLE_DATE_SHARD.match(table_id) is not None


@dataclass
class GcpLogBackendSpec:
    mode: str = "logging_api"
    bigquery_dataset: str = ""
    bigquery_default_table: str = ""
    bigquery_tables: dict[str, str] = field(default_factory=dict)
    bigquery_setup_required: bool = False
    gcs_bucket: str = ""
    gcs_prefix: str = ""
    gcs_setup_required: bool = False

    def uses_logging_api(self) -> bool:
        return self.mode == "logging_api"

    def uses_bigquery(self) -> bool:
        return self.mode == "bigquery"

    def uses_gcs(self) -> bool:
        return self.mode == "gcs"

    def to_acquisition_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": self.mode}
        if self.mode == "bigquery":
            bq: dict[str, Any] = {"setup_required": self.bigquery_setup_required}
            if self.bigquery_dataset.strip():
                bq["dataset"] = self.bigquery_dataset.strip()
            if self.bigquery_default_table.strip():
                bq["default_table"] = self.bigquery_default_table.strip()
            if self.bigquery_tables:
                bq["tables"] = {
                    k: v.strip()
                    for k, v in self.bigquery_tables.items()
                    if str(k).strip() and str(v).strip()
                }
            out["bigquery"] = bq
        elif self.mode == "gcs":
            gcs: dict[str, Any] = {"setup_required": self.gcs_setup_required}
            if self.gcs_bucket.strip():
                gcs["bucket"] = self.gcs_bucket.strip()
            if self.gcs_prefix.strip():
                gcs["prefix"] = self.gcs_prefix.strip()
            out["gcs"] = gcs
        return out

    @classmethod
    def from_acquisition_dict(cls, raw: Any) -> GcpLogBackendSpec:
        if not raw or not isinstance(raw, dict):
            return cls()
        mode = str(raw.get("mode") or "logging_api").strip().lower()
        if mode not in ("logging_api", "bigquery", "gcs"):
            mode = "logging_api"
        bq = raw.get("bigquery") if isinstance(raw.get("bigquery"), dict) else {}
        gcs = raw.get("gcs") if isinstance(raw.get("gcs"), dict) else {}
        tables_raw = bq.get("tables") if isinstance(bq.get("tables"), dict) else {}
        tables = {
            str(k).strip(): str(v).strip()
            for k, v in tables_raw.items()
            if str(k).strip() and str(v).strip()
        }
        return cls(
            mode=mode,
            bigquery_dataset=str(bq.get("dataset") or "").strip(),
            bigquery_default_table=str(bq.get("default_table") or "").strip(),
            bigquery_tables=tables,
            bigquery_setup_required=bool(bq.get("setup_required")),
            gcs_bucket=str(gcs.get("bucket") or "").strip(),
            gcs_prefix=str(gcs.get("prefix") or "").strip(),
            gcs_setup_required=bool(gcs.get("setup_required")),
        )


def extra_iam_for_backend(spec: GcpLogBackendSpec | None) -> set[str]:
    if spec is None:
        return set()
    return set(_EXTRA_IAM_BY_MODE.get(spec.mode, frozenset()))


def iam_actions_for_mode(mode: str) -> list[str]:
    """Read-only IAM actions required for a log backend mode (for UI / docs)."""
    return sorted(_EXTRA_IAM_BY_MODE.get(mode, frozenset()))


def apply_gcp_log_backend_iam(wanted: set[str], raw: Any) -> set[str]:
    """Merge kit IAM: add backend permissions, drop Logging API when using Export / Archive."""
    spec = GcpLogBackendSpec.from_acquisition_dict(raw)
    if spec.mode not in ("bigquery", "gcs"):
        return wanted
    out = set(wanted) - _LOGGING_API_ONLY
    out.update(_EXTRA_IAM_BY_MODE[spec.mode])
    return out


def cart_needs_gcp_log_backend(collector_names: list[str]) -> bool:
    return bool(GCP_LOGGING_COLLECTOR_IDS.intersection(collector_names))


def validate_gcp_log_backend_dict(raw: Any) -> dict[str, Any]:
    """Validate ``gcp_log_backend`` for kit build; return normalized acquisition dict."""
    spec = GcpLogBackendSpec.from_acquisition_dict(raw)
    if spec.mode not in ("logging_api", "bigquery", "gcs"):
        raise ValueError(f"Unknown gcp_log_backend mode: {spec.mode!r}")
    if spec.mode == "bigquery" and not spec.bigquery_dataset:
        raise ValueError("BigQuery Export requires gcp_log_backend.bigquery.dataset.")
    if spec.mode == "gcs" and not spec.gcs_bucket:
        raise ValueError("Cloud Storage Archive requires gcp_log_backend.gcs.bucket.")
    return spec.to_acquisition_dict()


def resolve_bigquery_table_candidates(
    collector: str,
    spec: GcpLogBackendSpec,
    artifact_params: dict[str, Any] | None = None,
) -> list[str]:
    """Table ids to try for a collector, most specific first.

    Union collectors (``bigquery_reads_all_tables``) read every listed table; the rest stop at
    the first table that yields rows. ``_Default`` is always the last-resort catch-all.
    """
    params = artifact_params or {}
    resolved = params.get("bigquery_tables")
    if isinstance(resolved, list) and any(str(t).strip() for t in resolved):
        return [str(t).strip() for t in resolved if str(t).strip()]
    explicit = str(params.get("bigquery_table") or "").strip()
    if explicit:
        return [explicit]
    mapped = spec.bigquery_tables.get(collector, "").strip()
    if mapped:
        return [mapped]
    if spec.bigquery_default_table.strip():
        return [spec.bigquery_default_table.strip()]
    out = [h for h in _COLLECTOR_BQ_TABLE_HINTS.get(collector, ()) if h.strip()]
    if _BQ_DEFAULT_TABLE_FALLBACK not in out:
        out.append(_BQ_DEFAULT_TABLE_FALLBACK)
    return out


def resolve_gcs_prefix_candidates(
    collector: str,
    spec: GcpLogBackendSpec,
    artifact_params: dict[str, Any] | None = None,
) -> list[str]:
    """Object prefixes to enumerate for a collector, joined onto the bucket's sink prefix.

    Union collectors (``bigquery_reads_all_tables``) read every listed prefix; the rest stop
    at the first prefix that yields objects. No hints → the sink prefix alone (full scan,
    rows still isolated by the collector's log filter).
    """
    params = artifact_params or {}
    explicit = str(params.get("gcs_prefix") or "").strip()
    base = explicit or spec.gcs_prefix.strip()
    base = f"{base.rstrip('/')}/" if base else ""
    hints = _COLLECTOR_GCS_PREFIX_HINTS.get(collector, ())
    if not hints:
        return [base]
    return [f"{base}{hint}" for hint in hints]


def uses_gcp_logging_api(raw: Any) -> bool:
    return GcpLogBackendSpec.from_acquisition_dict(raw).uses_logging_api()
