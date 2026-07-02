"""Tests for the GCP collection-strategy resolver (BigQuery / GCS / Log Explorer)."""

from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace

import pytest
from collector.engine.gcp_strategy_resolver import (
    COLLECTOR_MAP,
    STATUS_BIGQUERY,
    STATUS_LOG_EXPLORER,
    STATUS_NOT_COLLECTED,
    STATUS_STORAGE,
    BucketNotFoundError,
    DatasetNotFoundError,
    resolve_collection_strategy,
)
from google.api_core import exceptions as gcp_exc

PROJECT = "test-proj"
DATASET = "audit_ds"
TARGET_BQ = f"{PROJECT}.{DATASET}"
BUCKET = "audit-bucket"


# -- Fakes -------------------------------------------------------------------------------------


def _sink(destination: str, filter_: str = "") -> SimpleNamespace:
    return SimpleNamespace(destination=destination, filter=filter_)


def _bq_catchall_sink() -> SimpleNamespace:
    return _sink(f"bigquery.googleapis.com/projects/{PROJECT}/datasets/{DATASET}", "")


def _gcs_catchall_sink() -> SimpleNamespace:
    return _sink(f"storage.googleapis.com/{BUCKET}", "")


class FakeLoggingClient:
    def __init__(self, sinks=None, error=None) -> None:
        self._sinks = sinks or []
        self._error = error

    def list_sinks(self):
        if self._error is not None:
            raise self._error
        return list(self._sinks)


class FakeQueryJob:
    def __init__(self, cnt: int, timeout: bool = False) -> None:
        self._cnt = cnt
        self._timeout = timeout

    def result(self, timeout=None):
        if self._timeout:
            raise concurrent.futures.TimeoutError()
        return [{"cnt": self._cnt}]


class FakeBQClient:
    """Counts are keyed by a substring expected in the validation SQL (prefix or service value)."""

    def __init__(self, *, tables=None, counts=None, dataset_exists=True, timeout_keys=None) -> None:
        self._tables = tables or []
        self._counts = counts or {}
        self._dataset_exists = dataset_exists
        self._timeout_keys = timeout_keys or set()
        self.queries: list[str] = []

    def list_tables(self, dataset_ref):
        if not self._dataset_exists:
            raise gcp_exc.NotFound("dataset not found")
        return [SimpleNamespace(table_id=t) for t in self._tables]

    def query(self, sql):
        self.queries.append(sql)
        for key, cnt in self._counts.items():
            if key in sql:
                return FakeQueryJob(cnt, key in self._timeout_keys)
        return FakeQueryJob(0, False)


class FakeStorageClient:
    def __init__(self, *, objects=None, bucket_exists=True) -> None:
        self._objects = objects or {}  # prefix -> object count
        self._bucket_exists = bucket_exists

    def get_bucket(self, name):
        if not self._bucket_exists:
            raise gcp_exc.NotFound("bucket not found")
        return SimpleNamespace(name=name)

    def list_blobs(self, bucket, prefix=None, max_results=None):
        n = self._objects.get(prefix, 0)
        cap = max_results if max_results is not None else n
        return [SimpleNamespace(name=f"{prefix}obj{i}.json") for i in range(min(n, cap))]


def _resolve_bq(collectors, bq, logging_client, **kw):
    return resolve_collection_strategy(
        collectors, "bigquery", TARGET_BQ, PROJECT,
        bigquery_client=bq, logging_client=logging_client, **kw,
    )


# -- BigQuery ----------------------------------------------------------------------------------


def test_matching_table_no_service_filter_collects() -> None:
    bq = FakeBQClient(tables=["cloudaudit_googleapis_com_activity_20260630"])
    (r,) = _resolve_bq(["cloud_audit_admin"], bq, FakeLoggingClient())
    assert r.status == STATUS_BIGQUERY
    assert r.strategy_used == "bigquery"
    assert r.table_or_prefix == "cloudaudit_googleapis_com_activity_"
    assert r.reason is None
    assert r.has_service_filter is False
    assert bq.queries == []  # unambiguous table → no validation query needed


def test_matching_table_service_filter_no_rows_not_collected() -> None:
    bq = FakeBQClient(tables=["cloudaudit_googleapis_com_data_access_20260630"], counts={})
    (r,) = _resolve_bq(["secret_manager"], bq, FakeLoggingClient())
    assert r.status == STATUS_NOT_COLLECTED
    assert r.strategy_used == "none"
    assert "service 'secretmanager.googleapis.com' not present" in r.reason
    assert "Data Access logging may not be enabled" in r.reason
    assert bq.queries  # validation query ran for the shared table
    # The validation predicate must use BigQuery SQL dialect, not the Log Explorer spelling.
    assert any("protopayload_auditlog.serviceName" in q for q in bq.queries)
    assert not any("protoPayload.serviceName" in q for q in bq.queries)


def test_no_table_no_catchall_not_collected_with_suggested_filter() -> None:
    bq = FakeBQClient(tables=["some_other_table_20260630"])
    (r,) = _resolve_bq(["vpc_flow"], bq, FakeLoggingClient(sinks=[]))
    assert r.status == STATUS_NOT_COLLECTED
    assert "No sink routing" in r.reason
    assert COLLECTOR_MAP["vpc_flow"]["log_filter"] in r.reason  # suggested sink filter


def test_no_table_catchall_rows_found_collects() -> None:
    bq = FakeBQClient(tables=[], counts={"compute_googleapis_com_vpc_flows": 3})
    (r,) = _resolve_bq(["vpc_flow"], bq, FakeLoggingClient(sinks=[_bq_catchall_sink()]))
    assert r.status == STATUS_BIGQUERY
    assert "compute_googleapis_com_vpc_flows" in r.table_or_prefix
    assert bq.queries  # catch-all forces row-level validation


def test_no_table_catchall_no_rows_not_collected() -> None:
    bq = FakeBQClient(tables=[], counts={})
    (r,) = _resolve_bq(["vpc_flow"], bq, FakeLoggingClient(sinks=[_bq_catchall_sink()]))
    assert r.status == STATUS_NOT_COLLECTED
    assert "Catch-all sink configured" in r.reason


def test_shared_table_resolves_each_collector_independently() -> None:
    bq = FakeBQClient(
        tables=["cloudaudit_googleapis_com_data_access_20260630"],
        counts={"secretmanager.googleapis.com": 7, "storage.googleapis.com": 0},
    )
    res = _resolve_bq(["secret_manager", "storage_access"], bq, FakeLoggingClient())
    by_id = {r.collector_id: r for r in res}
    assert by_id["secret_manager"].status == STATUS_BIGQUERY
    assert by_id["storage_access"].status == STATUS_NOT_COLLECTED


def test_dataset_not_found_raises_before_resolution() -> None:
    bq = FakeBQClient(dataset_exists=False)
    with pytest.raises(DatasetNotFoundError):
        _resolve_bq(["cloud_audit_admin"], bq, FakeLoggingClient())


def test_sinks_permission_error_degrades_without_catchall(caplog) -> None:
    bq = FakeBQClient(tables=[])
    logging_client = FakeLoggingClient(error=gcp_exc.PermissionDenied("denied"))
    with caplog.at_level("WARNING"):
        (r,) = _resolve_bq(["vpc_flow"], bq, logging_client)
    assert r.status == STATUS_NOT_COLLECTED
    assert "No sink routing" in r.reason  # catch-all detection disabled, not assumed
    assert any("Could not list Log Router sinks" in m for m in caplog.messages)


def test_validation_timeout_defaults_to_collect_with_flag() -> None:
    bq = FakeBQClient(
        tables=["cloudaudit_googleapis_com_data_access_20260630"],
        counts={"secretmanager.googleapis.com": 0},
        timeout_keys={"secretmanager.googleapis.com"},
    )
    (r,) = _resolve_bq(["secret_manager"], bq, FakeLoggingClient())
    assert r.status == STATUS_BIGQUERY
    assert r.validation_timed_out is True


# -- Log Explorer ------------------------------------------------------------------------------


def test_log_explorer_always_collects_regardless_of_state() -> None:
    res = resolve_collection_strategy(
        ["cloud_audit_admin", "vpc_flow", "secret_manager"], "log_explorer"
    )
    assert {r.status for r in res} == {STATUS_LOG_EXPLORER}
    assert all(r.strategy_used == "log_explorer" for r in res)
    assert all(r.reason is None for r in res)


# -- Cloud Storage -----------------------------------------------------------------------------


def test_gcs_objects_exist_collects() -> None:
    storage = FakeStorageClient(objects={"cloudaudit.googleapis.com/activity/": 1})
    res = resolve_collection_strategy(
        ["cloud_audit_admin"], "storage", BUCKET, PROJECT,
        storage_client=storage, logging_client=FakeLoggingClient(),
    )
    (r,) = res
    assert r.status == STATUS_STORAGE
    assert r.strategy_used == "storage"
    assert r.table_or_prefix == "cloudaudit.googleapis.com/activity/"


def test_gcs_no_objects_not_collected() -> None:
    storage = FakeStorageClient(objects={})
    res = resolve_collection_strategy(
        ["cloud_audit_admin"], "storage", BUCKET, PROJECT,
        storage_client=storage, logging_client=FakeLoggingClient(sinks=[]),
    )
    (r,) = res
    assert r.status == STATUS_NOT_COLLECTED
    assert "no objects found under prefix" in r.reason


def test_gcs_catchall_no_objects_uses_catchall_reason() -> None:
    storage = FakeStorageClient(objects={})
    res = resolve_collection_strategy(
        ["cloud_audit_admin"], "storage", BUCKET, PROJECT,
        storage_client=storage, logging_client=FakeLoggingClient(sinks=[_gcs_catchall_sink()]),
    )
    (r,) = res
    assert r.status == STATUS_NOT_COLLECTED
    assert "Catch-all sink configured" in r.reason


def test_bucket_not_found_raises() -> None:
    storage = FakeStorageClient(bucket_exists=False)
    with pytest.raises(BucketNotFoundError):
        resolve_collection_strategy(
            ["cloud_audit_admin"], "storage", BUCKET, PROJECT,
            storage_client=storage, logging_client=FakeLoggingClient(),
        )


# -- Window scoping, table forms, conditionals, unions ------------------------------------


def _june_window() -> dict:
    from datetime import UTC, datetime

    return {
        "since": datetime(2026, 6, 1, tzinfo=UTC),
        "until": datetime(2026, 6, 30, tzinfo=UTC),
    }


def test_validation_partitioned_table_uses_exact_ref_and_timestamp() -> None:
    bq = FakeBQClient(
        tables=["cloudaudit_googleapis_com_data_access"],  # bare name → partitioned
        counts={"secretmanager.googleapis.com": 2},
    )
    (r,) = _resolve_bq(["secret_manager"], bq, FakeLoggingClient(), **_june_window())
    assert r.status == STATUS_BIGQUERY
    assert r.table_or_prefix == "cloudaudit_googleapis_com_data_access"  # no shard suffix
    sql = bq.queries[0]
    assert ".cloudaudit_googleapis_com_data_access`" in sql
    assert "_TABLE_SUFFIX" not in sql
    assert "timestamp >= TIMESTAMP('2026-06-01" in sql
    assert "timestamp <= TIMESTAMP('2026-06-30" in sql


def test_validation_sharded_table_uses_wildcard_and_table_suffix() -> None:
    bq = FakeBQClient(
        tables=["cloudaudit_googleapis_com_data_access_20260615"],
        counts={"secretmanager.googleapis.com": 2},
    )
    (r,) = _resolve_bq(["secret_manager"], bq, FakeLoggingClient(), **_june_window())
    assert r.status == STATUS_BIGQUERY
    assert r.table_or_prefix == "cloudaudit_googleapis_com_data_access_"
    sql = bq.queries[0]
    assert ".cloudaudit_googleapis_com_data_access_*`" in sql
    assert "_TABLE_SUFFIX BETWEEN '20260601' AND '20260630'" in sql


def test_windowed_broad_stream_zero_rows_reports_no_rows_for_window() -> None:
    bq = FakeBQClient(tables=["cloudaudit_googleapis_com_activity_20260615"], counts={})
    (r,) = _resolve_bq(["cloud_audit_admin"], bq, FakeLoggingClient(), **_june_window())
    assert r.status == STATUS_NOT_COLLECTED
    assert "no rows for window" in r.reason


def test_conditional_collector_absent_until_discovery_confirms_table() -> None:
    absent = FakeBQClient(tables=["cloudaudit_googleapis_com_activity_20260615"])
    (r,) = _resolve_bq(["gke_audit"], absent, FakeLoggingClient(sinks=[]))
    assert r.status == STATUS_NOT_COLLECTED
    assert "container.googleapis.com/apiserver" in r.reason

    present = FakeBQClient(
        tables=[
            "cloudaudit_googleapis_com_activity_20260615",
            "container_googleapis_com_apiserver_20260615",
        ]
    )
    (r,) = _resolve_bq(["gke_audit"], present, FakeLoggingClient(sinks=[]))
    assert r.status == STATUS_BIGQUERY
    assert r.tables == ["container_googleapis_com_apiserver"]


def test_vpc_flow_union_collects_when_either_stream_table_exists() -> None:
    bq = FakeBQClient(tables=["networkmanagement_googleapis_com_vpc_flows_20260615"])
    (r,) = _resolve_bq(["vpc_flow"], bq, FakeLoggingClient(sinks=[]))
    assert r.status == STATUS_BIGQUERY
    assert r.tables == ["networkmanagement_googleapis_com_vpc_flows"]

    both = FakeBQClient(
        tables=[
            "compute_googleapis_com_vpc_flows_20260615",
            "networkmanagement_googleapis_com_vpc_flows_20260615",
        ]
    )
    (r,) = _resolve_bq(["vpc_flow"], both, FakeLoggingClient(sinks=[]))
    assert sorted(r.tables) == [
        "compute_googleapis_com_vpc_flows",
        "networkmanagement_googleapis_com_vpc_flows",
    ]


def test_validation_scopes_selected_projects() -> None:
    bq = FakeBQClient(
        tables=["cloudaudit_googleapis_com_data_access_20260615"],
        counts={"secretmanager.googleapis.com": 1},
    )
    (r,) = _resolve_bq(
        ["secret_manager"], bq, FakeLoggingClient(), project_scope=["p1", "p2"]
    )
    assert r.status == STATUS_BIGQUERY
    sql = bq.queries[0]
    assert "STARTS_WITH(logName, 'projects/p1/')" in sql
    assert "STARTS_WITH(logName, 'projects/p2/')" in sql
