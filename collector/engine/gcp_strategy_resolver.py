"""Pre-flight resolution: decide HOW each selected collector's logs will actually be read.

The Acquire UI lets a client pick a collection strategy (Log Explorer direct API, BigQuery
Export, or Cloud Storage Archive). But choosing "BigQuery Export" doesn't mean their dataset
actually contains every selected log type — sinks are often wired for only some services. This
module confirms, per collector, that the data lands where the chosen backend expects, and
surfaces the gaps *explicitly* as NOT_COLLECTED with an actionable reason rather than silently
falling back to the direct API.

Ventra is read-only: this only inspects sinks/tables/objects; it never creates them.
"""

from __future__ import annotations

import concurrent.futures
import logging as _logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from collector.engine.gcp_log_backend import (
    bigquery_reads_all_tables,
    bigquery_table_hints,
    classify_bigquery_table,
    gcs_prefix_hints,
    strip_bigquery_date_shard,
)
from collector.engine.gcp_log_export import normalize_gcs_bucket, parse_bigquery_dataset

_LOG = _logging.getLogger(__name__)

# Resolution statuses.
STATUS_BIGQUERY = "COLLECT_BIGQUERY"
STATUS_STORAGE = "COLLECT_STORAGE"
STATUS_LOG_EXPLORER = "COLLECT_LOG_EXPLORER"
STATUS_NOT_COLLECTED = "NOT_COLLECTED"

# Strategy identifiers accepted as input and echoed back in ``strategy_used``.
STRATEGY_BIGQUERY = "bigquery"
STRATEGY_STORAGE = "storage"
STRATEGY_LOG_EXPLORER = "log_explorer"

_VALIDATION_TIMEOUT_S = 30.0
_VALIDATION_LOOKBACK_DAYS = 90


def _entry(
    log_name: str,
    log_filter: str,
    collector: str,
    *,
    bq_where: str | None = None,
    service_filter: str | None = None,
    service_label: str | None = None,
) -> dict[str, Any]:
    """One COLLECTOR_MAP row. Table and object routing derives from the backend hints so the
    reader and the resolver can never disagree about where a collector's rows live.

    ``service_filter`` is the Log Explorer dialect predicate (echoed to analysts);
    ``bq_where`` is the same predicate in BigQuery SQL dialect — validation COUNTs run in
    BigQuery, and the Log Explorer spelling silently matches nothing there.
    """
    return {
        "log_name": log_name,
        "log_filter": log_filter,
        "bq_tables": tuple(t for t in bigquery_table_hints(collector) if t != "_Default"),
        "gcs_prefixes": gcs_prefix_hints(collector),
        "bq_where": bq_where,
        "service_filter": service_filter,
        "service_label": service_label,
        "union": bigquery_reads_all_tables(collector),
    }


def _audit_view(stream: str, service: str, collector: str) -> dict[str, Any]:
    """serviceName view over a shared audit stream (a filter, not a separate log)."""
    return _entry(
        f"cloudaudit.googleapis.com/{stream}",
        f'logName:"cloudaudit.googleapis.com%2F{stream}" AND protoPayload.serviceName="{service}"',
        collector,
        bq_where=f"protopayload_auditlog.serviceName = '{service}'",
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
        'logName:("compute.googleapis.com%2Fvpc_flows" OR "networkmanagement.googleapis.com%2Fvpc_flows")',  # noqa: E501
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
        bq_where="jsonpayload_type_loadbalancerlogentry.cachedecision IS NOT NULL",
        service_filter="jsonPayload.cacheDecision:*",
        service_label="cacheDecision",
    ),
    "cloud_armor": _entry(
        "requests",
        f"{_LB_FILTER} AND jsonPayload.enforcedSecurityPolicy.name:*",
        "cloud_armor",
        bq_where="jsonpayload_type_loadbalancerlogentry.enforcedsecuritypolicy.name IS NOT NULL",
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
        'resource.type="cloud_function" AND logName:"cloudfunctions.googleapis.com%2Fcloud-functions"',  # noqa: E501
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

# Reason templates for NOT_COLLECTED — each explains exactly what is missing and how to fix it.
_REASON_NO_TABLE = (
    "No sink routing '{log_name}' to this dataset — no matching table found in '{dataset}'. "
    "Configure a Log Router sink with filter: {log_filter}"
)
_REASON_CATCHALL_NO_ROWS = (
    "Catch-all sink configured but no matching log entries found in dataset for this collector's "
    "time window. Logs may not have been generated yet or the log type may not be enabled."
)
_REASON_TABLE_NO_ROWS = (
    "Table '{table}' present but no rows for window (filter: {service_filter})."
)
_REASON_SERVICE_NOT_PRESENT = (
    "Table '{table}' present but service '{service}' not present; Data Access logging may not "
    "be enabled for it. Check your sink filter includes: {log_filter}"
)
_REASON_GCS_NO_OBJECTS = (
    "No sink routing '{log_name}' to this bucket — no objects found under prefix '{gcs_prefix}' "
    "in bucket '{bucket}'. Configure a Log Router sink with filter: {log_filter}"
)
_REASON_GCS_CATCHALL_NO_OBJECTS = (
    "Catch-all sink configured but no matching objects found under prefix '{gcs_prefix}' for this "
    "collector's time window. Logs may not have been generated yet or the log type may not be enabled."
)

_BQ_SINK_DEST = re.compile(r"^bigquery\.googleapis\.com/projects/([^/]+)/datasets/([^/]+)")
_GCS_SINK_DEST = re.compile(r"^storage\.googleapis\.com/([^/]+)")


class DatasetNotFoundError(Exception):
    """The configured BigQuery dataset does not exist in the project."""


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


def resolve_collection_strategy(
    selected_collectors: list[str],
    strategy: str,
    target: str = "",
    project_id: str = "",
    *,
    credentials: Any = None,
    logging_client: Any = None,
    bigquery_client: Any = None,
    storage_client: Any = None,
    query_timeout: float = _VALIDATION_TIMEOUT_S,
    lookback_days: int = _VALIDATION_LOOKBACK_DAYS,
    since: datetime | None = None,
    until: datetime | None = None,
    project_scope: list[str] | None = None,
    gcs_sink_prefix: str = "",
    discovery_out: dict[str, Any] | None = None,
    logger: Any = None,
) -> list[CollectorResolution]:
    """Resolve, per collector, how its logs will be read for ``strategy``.

    ``target`` is the BigQuery dataset (``project.dataset`` or ``dataset``) for the bigquery
    strategy, or the GCS bucket for the storage strategy; it is ignored for log_explorer.
    ``since``/``until`` scope the validation COUNTs to the analyst's window; ``project_scope``
    restricts them to the selected project IDs. ``discovery_out``, when supplied, is filled
    with what Phase 1 actually found (tables, known/noise/unknown classification, catch-all
    sinks). Clients may be injected for testing; otherwise they are built from ``credentials``.
    """
    log = logger or _LOG
    strategy = (strategy or "").strip().lower()
    collectors = [c for c in selected_collectors if c in COLLECTOR_MAP]

    if strategy == STRATEGY_LOG_EXPLORER:
        return [_log_explorer_resolution(c) for c in collectors]

    if strategy == STRATEGY_BIGQUERY:
        return _resolve_bigquery_strategy(
            collectors,
            target=target,
            project_id=project_id,
            credentials=credentials,
            logging_client=logging_client,
            bigquery_client=bigquery_client,
            query_timeout=query_timeout,
            lookback_days=lookback_days,
            since=since,
            until=until,
            project_scope=project_scope,
            discovery_out=discovery_out,
            log=log,
        )

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


# -- BigQuery ----------------------------------------------------------------------------------


def _resolve_bigquery_strategy(
    collectors: list[str],
    *,
    target: str,
    project_id: str,
    credentials: Any,
    logging_client: Any,
    bigquery_client: Any,
    query_timeout: float,
    lookback_days: int,
    since: datetime | None,
    until: datetime | None,
    project_scope: list[str] | None,
    discovery_out: dict[str, Any] | None,
    log: Any,
) -> list[CollectorResolution]:
    bq_project, dataset_id = parse_bigquery_dataset(target, default_project=project_id)
    client = bigquery_client or _build_bigquery_client(bq_project, credentials)

    # Dataset existence is checked up front so a missing dataset fails before any per-collector work.
    tables = _discover_tables(client, bq_project, dataset_id)

    bq_sinks, _gcs_sinks, sinks_ok = _discover_sinks(
        _resolve_logging_client(logging_client, project_id, credentials), log
    )
    has_catchall = _has_catchall_bigquery(bq_sinks, bq_project, dataset_id)

    if discovery_out is not None:
        classified = {base: classify_bigquery_table(base) for base in sorted(tables)}
        discovery_out.update(
            {
                "strategy": STRATEGY_BIGQUERY,
                "dataset": f"{bq_project}.{dataset_id}",
                "tables": {
                    base: ("date_sharded" if info["sharded"] else "partitioned")
                    for base, info in sorted(tables.items())
                },
                "classification": classified,
                "unknown_tables": [b for b, kind in classified.items() if kind == "unknown"],
                "catchall_sink": has_catchall,
                "sinks_listed": sinks_ok,
            }
        )

    validation = _ValidationContext(
        client=client,
        bq_project=bq_project,
        dataset_id=dataset_id,
        query_timeout=query_timeout,
        lookback_days=lookback_days,
        since=since,
        until=until,
        project_scope=list(project_scope or []),
    )

    return [
        _resolve_one_bigquery(
            cid,
            COLLECTOR_MAP[cid],
            dataset_id=dataset_id,
            tables=tables,
            has_catchall=has_catchall,
            validation=validation,
        )
        for cid in collectors
    ]


@dataclass
class _ValidationContext:
    client: Any
    bq_project: str
    dataset_id: str
    query_timeout: float
    lookback_days: int
    since: datetime | None
    until: datetime | None
    project_scope: list[str]

    @property
    def windowed(self) -> bool:
        return self.since is not None or self.until is not None


def _matched_forms(
    tables: dict[str, dict[str, bool]], candidate: str
) -> list[tuple[str, bool]]:
    """Discovered ``(table_base, is_sharded)`` forms for a candidate base name.

    Fan-out candidates (``cloudsql_googleapis_com``) match every child stream table.
    """
    out: list[tuple[str, bool]] = []
    for base, info in sorted(tables.items()):
        if base == candidate or base.startswith(f"{candidate}_"):
            if info["sharded"]:
                out.append((base, True))
            if info["partitioned"]:
                out.append((base, False))
    return out


def _resolve_one_bigquery(
    collector_id: str,
    entry: dict[str, Any],
    *,
    dataset_id: str,
    tables: dict[str, dict[str, bool]],
    has_catchall: bool,
    validation: _ValidationContext,
) -> CollectorResolution:
    log_filter = entry["log_filter"]
    bq_where = entry["bq_where"]
    is_union = entry["union"]

    matched: list[tuple[str, bool]] = []
    for candidate in entry["bq_tables"]:
        forms = _matched_forms(tables, candidate)
        matched.extend(forms)
        if forms and not is_union:
            break  # alternative names for one log — first present form wins

    if not matched:
        if not has_catchall:
            return _not_collected(
                collector_id,
                entry,
                _REASON_NO_TABLE.format(
                    log_name=entry["log_name"], dataset=dataset_id, log_filter=log_filter
                ),
            )
        # Catch-all sink routes everything here, but the table may not exist yet — probe rows
        # with the form-agnostic wildcard (matches both `base` and `base_YYYYMMDD`).
        probed: list[str] = []
        timed_out_any = False
        for candidate in entry["bq_tables"]:
            has_rows, timed_out = _run_validation_query(
                validation, candidate, sharded=None, where=bq_where
            )
            timed_out_any = timed_out_any or timed_out
            if has_rows or timed_out:
                probed.append(candidate)
                if not is_union:
                    break
        if probed:
            return _collected_bigquery(
                collector_id, entry, probed, sharded={}, validation_timed_out=timed_out_any
            )
        return _not_collected(collector_id, entry, _REASON_CATCHALL_NO_ROWS)

    sharded_by_base = {base: is_sharded for base, is_sharded in matched}
    needs_validation = bq_where is not None or validation.windowed
    if not needs_validation:
        return _collected_bigquery(
            collector_id, entry, [b for b, _ in matched], sharded=sharded_by_base
        )

    # Shared table (e.g. data_access) and/or windowed run: confirm rows exist before
    # promising data. Validation never silently falls back — 0 rows is reported as such.
    live: list[str] = []
    timed_out_any = False
    for base, is_sharded in matched:
        has_rows, timed_out = _run_validation_query(
            validation, base, sharded=is_sharded, where=bq_where
        )
        timed_out_any = timed_out_any or timed_out
        if has_rows or timed_out:
            live.append(base)
            if not is_union:
                break
    if live:
        return _collected_bigquery(
            collector_id, entry, live, sharded=sharded_by_base, validation_timed_out=timed_out_any
        )

    first_table = matched[0][0]
    service = entry["service_label"]
    if service and service.endswith(".googleapis.com"):
        reason = _REASON_SERVICE_NOT_PRESENT.format(
            table=first_table, service=service, log_filter=log_filter
        )
    else:
        reason = _REASON_TABLE_NO_ROWS.format(
            table=first_table, service_filter=entry["service_filter"] or "none"
        )
    return _not_collected(collector_id, entry, reason)


def _discover_tables(client: Any, bq_project: str, dataset_id: str) -> dict[str, dict[str, bool]]:
    """Phase 1 discovery: ``{table_base: {"sharded": bool, "partitioned": bool}}``.

    A base marked ``sharded`` was seen as ``base_YYYYMMDD`` daily tables; ``partitioned``
    means the bare table name exists (time-partitioned or plain). Both can be true when a
    sink was migrated between forms.
    """
    from google.api_core import exceptions as gcp_exc

    dataset_ref = f"{bq_project}.{dataset_id}"
    try:
        tables = list(client.list_tables(dataset_ref))
    except gcp_exc.NotFound as exc:
        raise DatasetNotFoundError(
            f"BigQuery dataset '{dataset_id}' was not found in project '{bq_project}'. "
            "Check the dataset name and that the export sink writes to it."
        ) from exc

    out: dict[str, dict[str, bool]] = {}
    for table in tables:
        table_id = str(getattr(table, "table_id", "") or "")
        if not table_id:
            continue
        base = strip_bigquery_date_shard(table_id)
        info = out.setdefault(base, {"sharded": False, "partitioned": False})
        if base == table_id:
            info["partitioned"] = True
        else:
            info["sharded"] = True
    return out


def _sql_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _run_validation_query(
    ctx: _ValidationContext,
    table_base: str,
    *,
    sharded: bool | None,
    where: str | None,
) -> tuple[bool, bool]:
    """Return ``(has_rows, timed_out)`` for the cheap COUNT(1) validation query.

    The query form follows the discovered table layout: date-sharded tables are pruned via
    ``_TABLE_SUFFIX`` over the ``base_*`` wildcard, partitioned tables via a plain timestamp
    range on the exact table. ``sharded=None`` (existence unknown — catch-all probing) uses
    the ``base*`` wildcard without ``_TABLE_SUFFIX`` so both layouts match.
    """
    from google.api_core import exceptions as gcp_exc

    if sharded is None:
        table_ref = f"`{ctx.bq_project}.{ctx.dataset_id}.{table_base}*`"
    elif sharded:
        table_ref = f"`{ctx.bq_project}.{ctx.dataset_id}.{table_base}_*`"
    else:
        table_ref = f"`{ctx.bq_project}.{ctx.dataset_id}.{table_base}`"

    clauses: list[str] = [where] if where else []
    if ctx.since is not None:
        clauses.append(f"timestamp >= TIMESTAMP('{ctx.since.isoformat()}')")
    if ctx.until is not None:
        clauses.append(f"timestamp <= TIMESTAMP('{ctx.until.isoformat()}')")
    if not ctx.windowed:
        clauses.append(
            f"timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {ctx.lookback_days} DAY)"
        )
    if sharded:
        if ctx.since is not None and ctx.until is not None:
            suffix_lo = ctx.since.strftime("%Y%m%d")
            suffix_hi = ctx.until.strftime("%Y%m%d")
            clauses.append(f"_TABLE_SUFFIX BETWEEN '{suffix_lo}' AND '{suffix_hi}'")
        elif not ctx.windowed:
            clauses.append(
                f"_TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), "
                f"INTERVAL {ctx.lookback_days} DAY))"
            )
    if ctx.project_scope:
        scope = " OR ".join(
            f"STARTS_WITH(logName, 'projects/{_sql_quote(p)}/')" for p in ctx.project_scope
        )
        clauses.append(f"({scope})")

    sql = (
        f"SELECT COUNT(1) as cnt\n"
        f"FROM {table_ref}\n"
        f"WHERE {' AND '.join(clauses) if clauses else 'TRUE'}\n"
        f"LIMIT 1"
    )
    try:
        result = ctx.client.query(sql).result(timeout=ctx.query_timeout)
    except concurrent.futures.TimeoutError:
        return (False, True)
    except gcp_exc.NotFound:
        # Wildcard matched no tables — no data of this type has been written yet.
        return (False, False)

    for row in result:
        return (int(_row_count(row) or 0) > 0, False)
    return (False, False)


def _row_count(row: Any) -> int:
    try:
        return int(row["cnt"])
    except (KeyError, TypeError, IndexError):
        pass
    value = getattr(row, "cnt", None)
    return int(value) if value is not None else 0


def _has_catchall_bigquery(bq_sinks: list[tuple[str, str]], bq_project: str, dataset_id: str) -> bool:
    for dest, filt in bq_sinks:
        if filt.strip():
            continue  # not a catch-all
        match = _BQ_SINK_DEST.match(dest)
        if match and match.group(1) == bq_project and match.group(2) == dataset_id:
            return True
    return False


# -- Cloud Storage -----------------------------------------------------------------------------


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

    _bq_sinks, gcs_sinks, sinks_ok = _discover_sinks(
        _resolve_logging_client(logging_client, project_id, credentials), log
    )
    has_catchall = _has_catchall_gcs(gcs_sinks, bucket_name)

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
    results: list[CollectorResolution] = []
    for cid in collectors:
        entry = COLLECTOR_MAP[cid]
        results.append(
            _resolve_one_storage(
                cid,
                entry,
                bucket_name=bucket_name,
                bucket=bucket,
                has_catchall=has_catchall,
                client=client,
                sink_prefix=sink_prefix,
            )
        )
    return results


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
                break  # alternative folder names for one log — first present form wins

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


# -- Log Router sinks --------------------------------------------------------------------------


def _discover_sinks(
    logging_client: Any, log: Any
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], bool]:
    """Return ``(bigquery_sinks, gcs_sinks, ok)`` as ``(destination, filter)`` pairs.

    ``ok`` is False when sinks could not be listed (permissions), which disables catch-all
    detection but does not fail resolution.
    """
    if logging_client is None:
        return [], [], False

    from google.api_core import exceptions as gcp_exc

    try:
        sinks = list(logging_client.list_sinks())
    except gcp_exc.GoogleAPIError:
        log.warning(
            "Could not list Log Router sinks — proceeding with table/object existence checks "
            "only (catch-all sink detection disabled)"
        )
        return [], [], False

    bq: list[tuple[str, str]] = []
    gcs: list[tuple[str, str]] = []
    for sink in sinks:
        dest = str(getattr(sink, "destination", "") or "")
        filt = str(getattr(sink, "filter", "") or "")
        if dest.startswith("bigquery.googleapis.com/projects/"):
            bq.append((dest, filt))
        elif dest.startswith("storage.googleapis.com/"):
            gcs.append((dest, filt))
    return bq, gcs, True


# -- Resolution builders -----------------------------------------------------------------------


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


def _collected_bigquery(
    collector_id: str,
    entry: dict[str, Any],
    tables: list[str],
    *,
    sharded: dict[str, bool],
    validation_timed_out: bool = False,
) -> CollectorResolution:
    # table_or_prefix keeps the analyst-facing form: `base_` for date-sharded daily tables
    # (queried as base_*), the bare base for partitioned tables.
    forms = [f"{t}_" if sharded.get(t) else t for t in tables]
    return CollectorResolution(
        collector_id=collector_id,
        collector_name=_display_name(collector_id),
        status=STATUS_BIGQUERY,
        strategy_used=STRATEGY_BIGQUERY,
        reason=None,
        table_or_prefix=" + ".join(forms) if forms else None,
        has_service_filter=entry["service_filter"] is not None,
        service_filter=entry["service_filter"],
        validation_timed_out=validation_timed_out,
        tables=list(tables),
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


# -- Clients / naming --------------------------------------------------------------------------


def _resolve_logging_client(logging_client: Any, project_id: str, credentials: Any) -> Any:
    if logging_client is not None:
        return logging_client
    if credentials is None:
        return None
    from google.cloud import logging_v2

    return logging_v2.Client(project=project_id or None, credentials=credentials)


def _build_bigquery_client(bq_project: str, credentials: Any) -> Any:
    from google.cloud import bigquery

    return bigquery.Client(project=bq_project or None, credentials=credentials)


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
    except Exception:  # noqa: BLE001 — display name is best-effort; fall back to the id.
        pass
    return collector_id.replace("_", " ").title()
