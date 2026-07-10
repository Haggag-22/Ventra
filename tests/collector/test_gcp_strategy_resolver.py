"""Tests for the GCP collection-strategy resolver (GCS / Log Explorer)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from collector.engine.gcp_strategy_resolver import (
    COLLECTOR_MAP,
    STATUS_LOG_EXPLORER,
    STATUS_NOT_COLLECTED,
    STATUS_STORAGE,
    BucketNotFoundError,
    resolve_collection_strategy,
)
from google.api_core import exceptions as gcp_exc

PROJECT = "test-proj"
BUCKET = "audit-bucket"


def _sink(destination: str, filter_: str = "") -> SimpleNamespace:
    return SimpleNamespace(destination=destination, filter=filter_)


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


class FakeStorageClient:
    def __init__(self, *, objects=None, bucket_exists=True) -> None:
        self._objects = objects or {}
        self._bucket_exists = bucket_exists

    def get_bucket(self, name):
        if not self._bucket_exists:
            raise gcp_exc.NotFound("bucket not found")
        return SimpleNamespace(name=name)

    def list_blobs(self, bucket, prefix=None, max_results=None):
        n = self._objects.get(prefix, 0)
        cap = max_results if max_results is not None else n
        return [SimpleNamespace(name=f"{prefix}obj{i}.json") for i in range(min(n, cap))]


def test_log_explorer_always_collects_regardless_of_state() -> None:
    res = resolve_collection_strategy(
        ["cloud_audit_admin", "vpc_flow", "secret_manager"], "log_explorer"
    )
    assert {r.status for r in res} == {STATUS_LOG_EXPLORER}
    assert all(r.strategy_used == "log_explorer" for r in res)
    assert all(r.reason is None for r in res)


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
    assert COLLECTOR_MAP["cloud_audit_admin"]["log_filter"] in r.reason


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


def test_sinks_permission_error_degrades_without_catchall(caplog) -> None:
    storage = FakeStorageClient(objects={})
    logging_client = FakeLoggingClient(error=gcp_exc.PermissionDenied("denied"))
    with caplog.at_level("WARNING"):
        (r,) = resolve_collection_strategy(
            ["vpc_flow"], "storage", BUCKET, PROJECT,
            storage_client=storage, logging_client=logging_client,
        )
    assert r.status == STATUS_NOT_COLLECTED
    assert "No sink routing" in r.reason
    assert any("Could not list Log Router sinks" in m for m in caplog.messages)
