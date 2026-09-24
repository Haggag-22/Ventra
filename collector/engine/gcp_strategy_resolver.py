"""Pre-flight resolution: decide HOW each selected collector's logs will actually be read."""

from __future__ import annotations

import logging as _logging
import re
from dataclasses import dataclass, field
from typing import Any

from collector.engine.gcp_log_backend import gcs_prefix_hints, gcs_reads_all_prefixes
from collector.engine.gcp_log_export import normalize_gcs_bucket

_LOG = _logging.getLogger(__name__)

STATUS_STORAGE = "COLLECT_STORAGE"
STATUS_LOG_EXPLORER = "COLLECT_LOG_EXPLORER"
STATUS_NOT_COLLECTED = "NOT_COLLECTED"

STRATEGY_STORAGE = "storage"
STRATEGY_LOG_EXPLORER = "log_explorer"

_GCS_SINK_DEST = re.compile(r"^storage\.googleapis\.com/([^/]+)")

_REASON_GCS_NO_OBJECTS = (
    "No sink routing '{log_name}' to this bucket — no objects found under prefix '{gcs_prefix}' "
    "in bucket '{bucket}'. Configure a Log Router sink with filter: {log_filter}"
)
_REASON_GCS_CATCHALL_NO_OBJECTS = (
    "Catch-all sink configured but no matching objects found under prefix '{gcs_prefix}' for this "
    "collector's time window. Logs may not have been generated yet or the log type may not be enabled."
)


class BucketNotFoundError(Exception):
    """The configured Cloud Storage bucket does not exist or is not accessible."""


@dataclass
class CollectorResolution:
    collector_id: str
    collector_name: str
    status: str
    strategy_used: str
    reason: str | None
    table_or_prefix: str | None
    has_service_filter: bool
    service_filter: str | None
    validation_timed_out: bool = False
    tables: list[str] = field(default_factory=list)


def _entry(
    log_name: str,
    log_filter: str,
    collector: str,
    *,
    service_filter: str | None = None,
    service_label: str | None = None,
) -> dict[str, Any]:
    return {
        "log_name": log_name,
        "log_filter": log_filter,
        "gcs_prefixes": gcs_prefix_hints(collector),
        "service_filter": service_filter,
        "service_label": service_label,
        "union": gcs_reads_all_prefixes(collector),
    }


def _audit_view(stream: str, service: str, collector: str) -> dict[str, Any]:
    return _entry(
        f"cloudaudit.googleapis.com/{stream}",
        f'logName:"cloudaudit.googleapis.com%2F{stream}" AND protoPayload.serviceName="{service}"',
        collector,
        service_filter=f'protoPayload.serviceName="{service}"',
        service_label=service,
    )


_LB_FILTER = 'resource.type="http_load_balancer" AND logName:"requests"'

COLLECTOR_MAP: dict[str, dict[str, Any]] = {
    "cloud_audit_admin": _entry(
        "cloudaudit.googleapis.com/activity",
        'logName:"cloudaudit.googleapis.com%2Factivity"',
        "cloud_audit_admin",
    ),
    "cloud_audit_system": _entry(
        "cloudaudit.googleapis.com/system_event",
        'logName:"cloudaudit.googleapis.com%2Fsystem_event"',
        "cloud_audit_system",
    ),
    "cloud_audit_data": _entry(
        "cloudaudit.googleapis.com/data_access",
        'logName:"cloudaudit.googleapis.com%2Fdata_access"',
        "cloud_audit_data",
    ),
    "login_events": _audit_view("data_access", "login.googleapis.com", "login_events"),
    "storage_access": _audit_view("data_access", "storage.googleapis.com", "storage_access"),
    "bigquery_audit": _audit_view("data_access", "bigquery.googleapis.com", "bigquery_audit"),
    "secret_manager": _audit_view("data_access", "secretmanager.googleapis.com", "secret_manager"),
    "vpc_flow": _entry(
        "compute.googleapis.com/vpc_flows",
        'logName:("compute.googleapis.com%2Fvpc_flows" OR "networkmanagement.googleapis.com%2Fvpc_flows")',
        "vpc_flow",
    ),
    "firewall_logs": _entry(
        "compute.googleapis.com/firewall",
        'logName:"compute.googleapis.com%2Ffirewall"',
        "firewall_logs",
    ),
    "cloud_nat": _entry(
        "compute.googleapis.com/nat_flows",
        'resource.type="nat_gateway" AND logName:"compute.googleapis.com%2Fnat_flows"',
        "cloud_nat",
    ),
    "load_balancer": _entry("requests", _LB_FILTER, "load_balancer"),
    "cloud_cdn": _entry(
        "requests",
        f"{_LB_FILTER} AND jsonPayload.cacheDecision:*",
        "cloud_cdn",
        service_filter="jsonPayload.cacheDecision:*",
        service_label="cacheDecision",
    ),
    "cloud_armor": _entry(
        "requests",
        f"{_LB_FILTER} AND jsonPayload.enforcedSecurityPolicy.name:*",
        "cloud_armor",
        service_filter="jsonPayload.enforcedSecurityPolicy.name:*",
        service_label="enforcedSecurityPolicy",
    ),
    "api_gateway": _entry(
        "apigateway.googleapis.com/requests",
        'logName:"apigateway.googleapis.com%2Frequests"',
        "api_gateway",
    ),
    "cloud_dns": _entry(
        "dns.googleapis.com/dns_queries",
        'resource.type="dns_query" AND logName:"dns.googleapis.com%2Fdns_queries"',
        "cloud_dns",
    ),
    "vm_logs": _entry(
        "syslog (and other logging-agent streams)",
        'resource.type="gce_instance" AND NOT logName:"compute.googleapis.com%2Fvpc_flows"',
        "vm_logs",
    ),
    "cloud_functions": _entry(
        "cloudfunctions.googleapis.com/cloud-functions",
        'resource.type="cloud_function" AND logName:"cloudfunctions.googleapis.com%2Fcloud-functions"',
        "cloud_functions",
    ),
    "cloud_sql": _entry(
        "cloudsql.googleapis.com/*",
        'resource.type="cloudsql_database"',
        "cloud_sql",
    ),
    "cloud_monitoring": _entry(
        "monitoring.googleapis.com",
        'logName:"monitoring.googleapis.com"',
        "cloud_monitoring",
    ),
    "gke_audit": _entry(
        "container.googleapis.com/apiserver",
        'logName:"container.googleapis.com%2Fapiserver" AND resource.type="k8s_cluster"',
        "gke_audit",
    ),
}


def resolve_collection_strategy(
    selected_collectors: list[str],
    strategy: str,
    target: str = "",
    project_id: str = "",
    *,
    credentials: Any = None,
    logging_client: Any = None,
    storage_client: Any = None,
    gcs_sink_prefix: str = "",
    discovery_out: dict[str, Any] | None = None,
    logger: Any = None,
    **kwargs: Any,
) -> list[CollectorResolution]:
    del kwargs
    log = logger or _LOG
    strategy = (strategy or "").strip().lower()
    collectors = [c for c in selected_collectors if c in COLLECTOR_MAP]

    if strategy == STRATEGY_LOG_EXPLORER:
        return [_log_explorer_resolution(c) for c in collectors]

    if strategy == STRATEGY_STORAGE:
        return _resolve_storage_strategy(
            collectors,
            target=target,
            project_id=project_id,
            credentials=credentials,
            logging_client=logging_client,
            storage_client=storage_client,
            gcs_sink_prefix=gcs_sink_prefix,
            discovery_out=discovery_out,
            log=log,
        )

    raise ValueError(f"Unknown collection strategy: {strategy!r}")


def _resolve_storage_strategy(
    collectors: list[str],
    *,
    target: str,
    project_id: str,
    credentials: Any,
    logging_client: Any,
    storage_client: Any,
    gcs_sink_prefix: str,
    discovery_out: dict[str, Any] | None,
    log: Any,
) -> list[CollectorResolution]:
    bucket_name = normalize_gcs_bucket(target)
    client = storage_client or _build_storage_client(credentials)
    bucket = _get_bucket(client, bucket_name)

    _gcs_sinks, sinks_ok = _discover_gcs_sinks(
        _resolve_logging_client(logging_client, project_id, credentials), log
    )
    has_catchall = _has_catchall_gcs(_gcs_sinks, bucket_name)

    if discovery_out is not None:
        discovery_out.update(
            {
                "strategy": STRATEGY_STORAGE,
                "bucket": bucket_name,
                "catchall_sink": has_catchall,
                "sinks_listed": sinks_ok,
            }
        )

    sink_prefix = f"{gcs_sink_prefix.strip().strip('/')}/" if gcs_sink_prefix.strip() else ""
    return [
        _resolve_one_storage(
            cid,
            COLLECTOR_MAP[cid],
            bucket_name=bucket_name,
            bucket=bucket,
            has_catchall=has_catchall,
            client=client,
            sink_prefix=sink_prefix,
        )
        for cid in collectors
    ]


def _resolve_one_storage(
    collector_id: str,
    entry: dict[str, Any],
    *,
    bucket_name: str,
    bucket: Any,
    has_catchall: bool,
    client: Any,
    sink_prefix: str,
) -> CollectorResolution:
    log_filter = entry["log_filter"]
    prefixes = [f"{sink_prefix}{p}" for p in entry["gcs_prefixes"]] or [sink_prefix]

    present: list[str] = []
    for gcs_prefix in prefixes:
        if list(client.list_blobs(bucket, prefix=gcs_prefix, max_results=1)):
            present.append(gcs_prefix)
            if not entry["union"]:
                break

    if present:
        return _collected_storage(collector_id, entry, present)
    if has_catchall:
        return _not_collected(
            collector_id, entry, _REASON_GCS_CATCHALL_NO_OBJECTS.format(gcs_prefix=prefixes[0])
        )
    return _not_collected(
        collector_id,
        entry,
        _REASON_GCS_NO_OBJECTS.format(
            log_name=entry["log_name"],
            gcs_prefix=prefixes[0],
            bucket=bucket_name,
            log_filter=log_filter,
        ),
    )


def _get_bucket(client: Any, bucket_name: str) -> Any:
    from google.api_core import exceptions as gcp_exc

    try:
        return client.get_bucket(bucket_name)
    except gcp_exc.NotFound as exc:
        raise BucketNotFoundError(
            f"Cloud Storage bucket '{bucket_name}' was not found. Check the bucket name and "
            "that the export sink writes to it."
        ) from exc
    except gcp_exc.Forbidden as exc:
        raise BucketNotFoundError(
            f"Cloud Storage bucket '{bucket_name}' is not accessible with the current credentials."
        ) from exc


def _has_catchall_gcs(gcs_sinks: list[tuple[str, str]], bucket_name: str) -> bool:
    for dest, filt in gcs_sinks:
        if filt.strip():
            continue
        match = _GCS_SINK_DEST.match(dest)
        if match and match.group(1) == bucket_name:
            return True
    return False


def _discover_gcs_sinks(logging_client: Any, log: Any) -> tuple[list[tuple[str, str]], bool]:
    if logging_client is None:
        return [], False

    from google.api_core import exceptions as gcp_exc

    try:
        sinks = list(logging_client.list_sinks())
    except gcp_exc.GoogleAPIError:
        log.warning(
            "Could not list Log Router sinks — proceeding with object existence checks "
            "only (catch-all sink detection disabled)"
        )
        return [], False

    gcs: list[tuple[str, str]] = []
    for sink in sinks:
        dest = str(getattr(sink, "destination", "") or "")
        filt = str(getattr(sink, "filter", "") or "")
        if dest.startswith("storage.googleapis.com/"):
            gcs.append((dest, filt))
    return gcs, True


def _log_explorer_resolution(collector_id: str) -> CollectorResolution:
    entry = COLLECTOR_MAP[collector_id]
    return CollectorResolution(
        collector_id=collector_id,
        collector_name=_display_name(collector_id),
        status=STATUS_LOG_EXPLORER,
        strategy_used=STRATEGY_LOG_EXPLORER,
        reason=None,
        table_or_prefix=None,
        has_service_filter=entry["service_filter"] is not None,
        service_filter=entry["service_filter"],
    )


def _collected_storage(
    collector_id: str, entry: dict[str, Any], gcs_prefixes: list[str]
) -> CollectorResolution:
    return CollectorResolution(
        collector_id=collector_id,
        collector_name=_display_name(collector_id),
        status=STATUS_STORAGE,
        strategy_used=STRATEGY_STORAGE,
        reason=None,
        table_or_prefix=" + ".join(gcs_prefixes) if gcs_prefixes else None,
        has_service_filter=entry["service_filter"] is not None,
        service_filter=entry["service_filter"],
        tables=list(gcs_prefixes),
    )


def _not_collected(collector_id: str, entry: dict[str, Any], reason: str) -> CollectorResolution:
    return CollectorResolution(
        collector_id=collector_id,
        collector_name=_display_name(collector_id),
        status=STATUS_NOT_COLLECTED,
        strategy_used="none",
        reason=reason,
        table_or_prefix=None,
        has_service_filter=entry["service_filter"] is not None,
        service_filter=entry["service_filter"],
    )


def _resolve_logging_client(logging_client: Any, project_id: str, credentials: Any) -> Any:
    if logging_client is not None:
        return logging_client
    if credentials is None:
        return None
    from google.cloud import logging_v2

    return logging_v2.Client(project=project_id or None, credentials=credentials)


def _build_storage_client(credentials: Any) -> Any:
    from google.cloud import storage

    return storage.Client(credentials=credentials)


def _display_name(collector_id: str) -> str:
    try:
        from collector.engine.registry import GCP_REGISTRY

        cls = GCP_REGISTRY.get(collector_id)
        description = getattr(cls, "description", "") if cls is not None else ""
        if description:
            return description
    except Exception:  # noqa: BLE001
        pass
    return collector_id.replace("_", " ").title()
