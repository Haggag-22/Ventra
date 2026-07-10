"""Tests for GCP GCS log export readers."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from collector.engine.gcp_log_export import (
    entry_in_window,
    iter_gcs_log_entries,
    matches_gcp_log_filter,
    normalize_gcs_bucket,
    normalize_log_entry,
)
from collector.lib.limits import UNLIMITED_RECORDS


def test_normalize_gcs_bucket() -> None:
    assert normalize_gcs_bucket("gs://my-bucket/path") == "my-bucket/path"


def test_normalize_log_entry_aliases() -> None:
    row = normalize_log_entry({"log_name": "projects/p/logs/syslog", "insert_id": "1"})
    assert row["logName"] == "projects/p/logs/syslog"
    assert row["insertId"] == "1"


def test_matches_gcp_log_filter_logname() -> None:
    entry = {"logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity"}
    assert matches_gcp_log_filter(entry, 'logName:"cloudaudit.googleapis.com%2Factivity"')


def test_entry_in_window() -> None:
    entry = {"timestamp": "2026-01-15T12:00:00Z"}
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 2, 1, tzinfo=UTC)
    assert entry_in_window(entry, start, end)


def _fake_blob(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


class _FakeIterator:
    def __init__(self, blobs):
        self._blobs = blobs

    def __iter__(self):
        return iter(self._blobs)


def test_iter_gcs_log_entries_filters_and_yields(monkeypatch) -> None:
    blobs = [
        _fake_blob("prefix/cloudaudit.googleapis.com/activity/2026/01/15/log.json"),
    ]
    payload = b'{"logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity", "timestamp": "2026-01-15T12:00:00Z"}'

    class FakeBucket:
        def blob(self, name):
            return SimpleNamespace(
                download_as_bytes=lambda: payload,
            )

    class FakeClient:
        def bucket(self, name):
            return FakeBucket()

        def list_blobs(self, bucket, prefix=None):
            return _FakeIterator(blobs)

    monkeypatch.setattr(
        "google.cloud.storage.Client",
        lambda credentials=None: FakeClient(),
    )

    rows = list(
        iter_gcs_log_entries(
            credentials=None,
            bucket_name="my-bucket",
            prefixes=["prefix/cloudaudit.googleapis.com/activity/"],
            log_filter='logName:"cloudaudit.googleapis.com%2Factivity"',
            start=None,
            end=None,
            max_records=UNLIMITED_RECORDS,
        )
    )
    assert len(rows) == 1
    assert "cloudaudit" in rows[0]["logName"]


def test_iter_gcs_log_entries_parallel_listing(monkeypatch) -> None:
    listed: list[str] = []

    class FakeBucket:
        def blob(self, name):
            return SimpleNamespace(download_as_bytes=lambda: b"{}")

    class FakeClient:
        def bucket(self, name):
            return FakeBucket()

        def list_blobs(self, bucket, prefix=None):
            listed.append(prefix or "")
            return iter([])

    monkeypatch.setattr(
        "google.cloud.storage.Client",
        lambda credentials=None: FakeClient(),
    )

    list(
        iter_gcs_log_entries(
            credentials=None,
            bucket_name="b",
            prefixes=["a/", "b/"],
            log_filter="",
            start=None,
            end=None,
            max_records=10,
        )
    )
    assert sorted(listed) == ["a/", "b/"]


def _run_iter(monkeypatch, payload: bytes, log_filter: str, max_records: int):
    blobs = [_fake_blob("prefix/requests/2026/01/15/log.json")]

    class FakeBucket:
        def blob(self, name):
            return SimpleNamespace(download_as_bytes=lambda: payload)

    class FakeClient:
        def bucket(self, name):
            return FakeBucket()

        def list_blobs(self, bucket, prefix=None):
            return _FakeIterator(blobs)

    monkeypatch.setattr("google.cloud.storage.Client", lambda credentials=None: FakeClient())
    return list(
        iter_gcs_log_entries(
            credentials=None,
            bucket_name="b",
            prefixes=["prefix/requests/"],
            log_filter=log_filter,
            start=None,
            end=None,
            max_records=max_records,
        )
    )


def test_iter_gcs_duckdb_and_python_agree_with_malformed_lines(monkeypatch) -> None:
    """DuckDB-on and DuckDB-off must yield identical rows; malformed NDJSON lines are dropped
    by the (unchanged) Python parse before either filter path sees them."""
    good1 = (
        '{"logName":"projects/p/logs/requests","resource":{"type":"http_load_balancer"},'
        '"jsonPayload":{"cacheDecision":"HIT"}}'
    )
    bad = "{not valid json at all"
    # snake_case + missing fields exercise schema variance
    good2 = '{"log_name":"projects/p/logs/requests","resource":{"type":"http_load_balancer"}}'
    nonmatch = '{"logName":"projects/p/logs/other","resource":{"type":"gce_instance"}}'
    payload = ("\n".join([good1, bad, good2, nonmatch])).encode("utf-8")
    log_filter = 'resource.type="http_load_balancer" AND logName:"requests"'

    monkeypatch.setenv("VENTRA_GCP_DUCKDB_FILTER", "1")
    duck_rows = _run_iter(monkeypatch, payload, log_filter, UNLIMITED_RECORDS)
    monkeypatch.setenv("VENTRA_GCP_DUCKDB_FILTER", "0")
    py_rows = _run_iter(monkeypatch, payload, log_filter, UNLIMITED_RECORDS)

    assert duck_rows == py_rows
    assert len(duck_rows) == 2  # good1 + good2; bad dropped, nonmatch filtered
    assert {r["logName"] for r in duck_rows} == {"projects/p/logs/requests"}


def test_iter_gcs_duckdb_and_python_agree_with_max_records(monkeypatch) -> None:
    rows = [
        f'{{"logName":"projects/p/logs/requests","resource":{{"type":"http_load_balancer"}},"i":{i}}}'
        for i in range(50)
    ]
    payload = "\n".join(rows).encode("utf-8")
    f = 'logName:"requests"'
    monkeypatch.setenv("VENTRA_GCP_DUCKDB_FILTER", "1")
    duck_rows = _run_iter(monkeypatch, payload, f, 10)
    monkeypatch.setenv("VENTRA_GCP_DUCKDB_FILTER", "0")
    py_rows = _run_iter(monkeypatch, payload, f, 10)
    assert duck_rows == py_rows
    assert len(duck_rows) == 10
    assert [r["i"] for r in duck_rows] == list(range(10))  # order + truncation preserved
