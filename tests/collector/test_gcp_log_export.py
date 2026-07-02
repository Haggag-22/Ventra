"""Tests for GCP BigQuery / GCS log export readers."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

from collector.engine.gcp_log_backend import GcpLogBackendSpec, resolve_bigquery_table_candidates
from collector.engine.gcp_log_export import (
    bigquery_table_patterns,
    check_bigquery_log_dataset,
    entry_in_window,
    iter_bigquery_log_entries,
    matches_gcp_log_filter,
    normalize_log_entry,
    parse_bigquery_dataset,
)
from collector.lib.limits import UNLIMITED_RECORDS
from google.api_core import exceptions as gcp_exc


def test_parse_bigquery_dataset_with_project() -> None:
    assert parse_bigquery_dataset("my-proj.audit_logs") == ("my-proj", "audit_logs")


def test_parse_bigquery_dataset_default_project() -> None:
    assert parse_bigquery_dataset("audit_logs", default_project="my-proj") == ("my-proj", "audit_logs")


def test_check_bigquery_log_dataset_found() -> None:
    class FakeClient:
        def list_tables(self, dataset_ref: str):
            assert dataset_ref == "my-proj.audit_logs"
            return [SimpleNamespace(table_id="cloudaudit_googleapis_com_activity_20250628")]

    with patch("google.cloud.bigquery.Client", return_value=FakeClient()):
        check = check_bigquery_log_dataset(
            credentials=object(),
            dataset="my-proj.audit_logs",
        )
    assert check.found is True
    assert check.ref == "my-proj.audit_logs"
    assert check.table_count == 1


def test_check_bigquery_log_dataset_not_found() -> None:
    class FakeClient:
        def list_tables(self, dataset_ref: str):
            raise gcp_exc.NotFound("missing")

    with patch("google.cloud.bigquery.Client", return_value=FakeClient()):
        check = check_bigquery_log_dataset(
            credentials=object(),
            dataset="my-proj.audit_logs",
        )
    assert check.found is False
    assert "not found" in check.message.lower()


def test_bigquery_table_patterns_includes_daily_shard_wildcard() -> None:
    assert bigquery_table_patterns("cloudaudit_googleapis_com_activity") == [
        ("cloudaudit_googleapis_com_activity", False),
        ("cloudaudit_googleapis_com_activity_*", True),
    ]


def test_bigquery_table_patterns_default_table_is_exact_only() -> None:
    assert bigquery_table_patterns("_Default") == [("_Default", False)]


def test_resolve_bigquery_table_uses_collector_hint() -> None:
    spec = GcpLogBackendSpec(mode="bigquery", bigquery_dataset="p.ds")
    tables = resolve_bigquery_table_candidates("cloud_audit_admin", spec)
    assert tables[0] == "cloudaudit_googleapis_com_activity"
    assert "_Default" in tables


def test_resolve_bigquery_table_explicit_map() -> None:
    spec = GcpLogBackendSpec(
        mode="bigquery",
        bigquery_dataset="p.ds",
        bigquery_tables={"cloud_audit_admin": "custom_activity"},
    )
    assert resolve_bigquery_table_candidates("cloud_audit_admin", spec) == ["custom_activity"]


def test_matches_admin_activity_log_name() -> None:
    entry = {
        "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "global", "labels": {}},
    }
    filt = 'logName:"cloudaudit.googleapis.com%2Factivity"'
    assert matches_gcp_log_filter(entry, filt)


def test_matches_resource_type_and_not_log_name() -> None:
    entry = {
        "logName": "projects/p/logs/syslog",
        "resource": {"type": "gce_instance", "labels": {}},
    }
    filt = 'resource.type="gce_instance" AND NOT logName:"compute.googleapis.com%2Fvpc_flows"'
    assert matches_gcp_log_filter(entry, filt)


def test_matches_login_events_filter() -> None:
    entry = {
        "logName": "projects/p/logs/cloudaudit.googleapis.com%2Fdata_access",
        "protoPayload": {"methodName": "google.login"},
    }
    filt = (
        'logName:"cloudaudit.googleapis.com%2Fdata_access" '
        'AND protoPayload.methodName=("google.login" OR "google.iam.admin.v1.CreateServiceAccountKey")'
    )
    assert matches_gcp_log_filter(entry, filt)


def test_matches_gke_cluster_labels() -> None:
    entry = {
        "resource": {
            "type": "k8s_cluster",
            "labels": {"cluster_name": "prod", "location": "us-central1"},
        }
    }
    filt = 'resource.type="k8s_cluster" AND resource.labels.cluster_name="prod"'
    assert matches_gcp_log_filter(entry, filt)


def test_entry_in_window_unbounded() -> None:
    entry = {"timestamp": "2026-01-01T00:00:00Z"}
    assert entry_in_window(entry, None, None) is True


def test_iter_bigquery_log_entries_paginates() -> None:
    ts = datetime(2026, 6, 28, 12, 0, tzinfo=UTC)
    row = {
        "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": ts,
        "resource": {"type": "global", "labels": {}},
    }

    class FakeJob:
        def __init__(self, rows: list[dict]) -> None:
            self._rows = rows

        def result(self):
            return list(self._rows)

    class FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        def query(self, sql, job_config=None):
            self.calls += 1
            if self.calls == 1:
                return FakeJob([dict(row) for _ in range(10_000)])
            if self.calls == 2:
                return FakeJob([dict(row)])
            return FakeJob([])

    start = datetime(2026, 6, 28, tzinfo=UTC)
    end = datetime(2026, 6, 30, tzinfo=UTC)
    with patch("google.cloud.bigquery.Client", return_value=FakeClient()):
        out = list(
            iter_bigquery_log_entries(
                credentials=object(),
                project_id="p",
                dataset="p.ds",
                tables=["cloudaudit_googleapis_com_activity"],
                log_filter='logName:"cloudaudit.googleapis.com%2Factivity"',
                start=start,
                end=end,
                max_records=UNLIMITED_RECORDS,
            )
        )
    assert len(out) == 10_001


def test_normalize_log_entry_aliases() -> None:
    row = {"log_name": "x", "timestamp": datetime(2026, 1, 1, tzinfo=UTC)}
    out = normalize_log_entry(row)
    assert out["logName"] == "x"
    assert out["timestamp"].endswith("Z")


# -- Full pagination, caps, table forms, unions, scoping ----------------------------------


def _bq_row(ts: datetime, insert_id: str, log_name: str = "projects/p/logs/syslog") -> dict:
    return {
        "logName": log_name,
        "timestamp": ts,
        "insertId": insert_id,
        "resource": {"type": "gce_instance", "labels": {}},
    }


class RecordingBQClient:
    """Routes query() by table-reference substring; records every SQL + parameters."""

    def __init__(self, behaviors: list[tuple[str, object]]) -> None:
        self._behaviors = behaviors  # (table_ref_substring, rows | list-of-pages | exception)
        self.sqls: list[str] = []
        self.params: list[dict[str, object]] = []
        self._page_cursor: dict[str, int] = {}

    def query(self, sql, job_config=None):
        self.sqls.append(sql)
        values: dict[str, object] = {}
        if job_config is not None:
            for p in job_config.query_parameters:
                values[p.name] = p.value
        self.params.append(values)
        for key, behavior in self._behaviors:
            if key not in sql:
                continue
            if isinstance(behavior, Exception):
                raise behavior
            if behavior and isinstance(behavior[0], list):  # multi-page: consume in order
                idx = self._page_cursor.get(key, 0)
                page = behavior[idx] if idx < len(behavior) else []
                self._page_cursor[key] = idx + 1
                return SimpleNamespace(result=lambda p=page: list(p))
            return SimpleNamespace(result=lambda b=behavior: list(b))
        return SimpleNamespace(result=lambda: [])


def _iter_bq(client, **kw):
    defaults = dict(
        credentials=object(),
        project_id="p",
        dataset="p.ds",
        log_filter="",
        start=datetime(2026, 6, 1, tzinfo=UTC),
        end=datetime(2026, 6, 30, tzinfo=UTC),
        max_records=UNLIMITED_RECORDS,
    )
    defaults.update(kw)
    with patch("google.cloud.bigquery.Client", return_value=client):
        return list(iter_bigquery_log_entries(**defaults))


def test_bq_explicit_cap_honored() -> None:
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    pages = [
        [_bq_row(ts, f"id{i}") for i in range(10_000)],
        [_bq_row(ts, f"id2-{i}") for i in range(2_000)],
    ]
    client = RecordingBQClient([("syslog", pages)])
    out = _iter_bq(client, tables=["syslog"], max_records=12_000)
    assert len(out) == 12_000
    # The second page asks for exactly the remaining records, not another full page.
    assert client.params[1]["page_limit"] == 2_000


def test_bq_partitioned_table_uses_exact_ref_without_table_suffix() -> None:
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    client = RecordingBQClient(
        [("`p.ds.cloudaudit_googleapis_com_activity`", [_bq_row(ts, "a")])]
    )
    out = _iter_bq(client, tables=["cloudaudit_googleapis_com_activity"])
    assert len(out) == 1
    assert "`p.ds.cloudaudit_googleapis_com_activity`" in client.sqls[0]
    assert "_TABLE_SUFFIX" not in client.sqls[0]


def test_bq_sharded_dataset_switches_to_wildcard_and_table_suffix() -> None:
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    client = RecordingBQClient(
        [
            ("`p.ds.cloudaudit_googleapis_com_activity`", gcp_exc.NotFound("no exact table")),
            ("`p.ds.cloudaudit_googleapis_com_activity_*`", [_bq_row(ts, "a")]),
        ]
    )
    out = _iter_bq(client, tables=["cloudaudit_googleapis_com_activity"])
    assert len(out) == 1
    wildcard_sql = client.sqls[1]
    assert "cloudaudit_googleapis_com_activity_*" in wildcard_sql
    assert "_TABLE_SUFFIX BETWEEN" in wildcard_sql
    assert client.params[1]["suffix_start"] == "20260601"
    assert client.params[1]["suffix_end"] == "20260630"


def test_vpc_flows_union_returns_both_streams() -> None:
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    client = RecordingBQClient(
        [
            (
                "`p.ds.compute_googleapis_com_vpc_flows`",
                [_bq_row(ts, "compute-1", "projects/p/logs/compute.googleapis.com%2Fvpc_flows")],
            ),
            (
                "`p.ds.networkmanagement_googleapis_com_vpc_flows`",
                [_bq_row(ts, "nm-1", "projects/p/logs/networkmanagement.googleapis.com%2Fvpc_flows")],
            ),
        ]
    )
    out = _iter_bq(
        client,
        tables=[
            "compute_googleapis_com_vpc_flows",
            "networkmanagement_googleapis_com_vpc_flows",
        ],
        read_all_tables=True,
    )
    assert [r["insertId"] for r in out] == ["compute-1", "nm-1"]


def test_alternative_table_names_stop_at_first_match_without_union() -> None:
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    client = RecordingBQClient(
        [
            ("`p.ds.requests`", [_bq_row(ts, "req-1")]),
            ("`p.ds.compute_googleapis_com_requests`", [_bq_row(ts, "dup-1")]),
        ]
    )
    out = _iter_bq(client, tables=["requests", "compute_googleapis_com_requests"])
    assert [r["insertId"] for r in out] == ["req-1"]  # alternate name never re-read
    assert not any("compute_googleapis_com_requests" in s for s in client.sqls)


def test_window_and_project_scope_applied_to_every_bq_query() -> None:
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    client = RecordingBQClient(
        [
            ("`p.ds.compute_googleapis_com_vpc_flows`", [_bq_row(ts, "a", "projects/p1/logs/x")]),
            ("`p.ds.networkmanagement_googleapis_com_vpc_flows`", [_bq_row(ts, "b", "projects/p2/logs/x")]),
        ]
    )
    out = _iter_bq(
        client,
        tables=[
            "compute_googleapis_com_vpc_flows",
            "networkmanagement_googleapis_com_vpc_flows",
        ],
        read_all_tables=True,
        project_scope=["p1", "p2"],
    )
    assert len(out) == 2
    for sql, params in zip(client.sqls, client.params, strict=True):
        assert "timestamp >= TIMESTAMP(@ts_start)" in sql
        assert "timestamp <= TIMESTAMP(@ts_end)" in sql
        assert "STARTS_WITH(logName, @project_scope_0)" in sql
        assert params["project_scope_0"] == "projects/p1/"
        assert params["project_scope_1"] == "projects/p2/"


def test_bq_quota_errors_delay_but_never_cap(monkeypatch) -> None:
    monkeypatch.setattr("collector.engine.gcp_log_export.time.sleep", lambda s: None)
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    rows = [_bq_row(ts, "a")]
    calls = {"n": 0}

    class QuotaThenRows:
        def query(self, sql, job_config=None):
            calls["n"] += 1
            if calls["n"] <= 3:
                raise gcp_exc.ResourceExhausted("429 read quota")
            return SimpleNamespace(result=lambda: list(rows))

    out = _iter_bq(QuotaThenRows(), tables=["syslog"])
    assert [r["insertId"] for r in out] == ["a"]
    assert calls["n"] == 4  # three 429s retried, page re-issued until it succeeds


def test_gcs_reads_all_objects_prunes_dates_and_scopes_projects() -> None:
    import json as _json

    def _blob(name: str, entries: list[dict]) -> SimpleNamespace:
        data = "\n".join(_json.dumps(e) for e in entries).encode()
        return SimpleNamespace(name=name, download_as_bytes=lambda d=data: d)

    in_window = {
        "logName": "projects/p1/logs/syslog",
        "timestamp": "2026-06-15T10:00:00Z",
        "insertId": "keep",
    }
    other_project = dict(in_window, logName="projects/other/logs/syslog", insertId="drop-project")
    blobs = [
        _blob("syslog/2026/06/15/00:00_a.json", [in_window, other_project]),
        _blob("syslog/2025/01/01/00:00_b.json", [dict(in_window, insertId="drop-date")]),
        _blob("syslog/2026/06/16/readme.txt", []),
    ]
    downloaded: list[str] = []

    class FakeStorage:
        def bucket(self, name):
            return SimpleNamespace(name=name)

        def list_blobs(self, bucket, prefix=None):
            assert prefix == "syslog/"
            for b in blobs:
                yield SimpleNamespace(
                    name=b.name,
                    download_as_bytes=lambda b=b: downloaded.append(b.name) or b.download_as_bytes(),
                )

    from collector.engine.gcp_log_export import iter_gcs_log_entries

    with patch("google.cloud.storage.Client", return_value=FakeStorage()):
        out = list(
            iter_gcs_log_entries(
                credentials=object(),
                bucket_name="gs://logs-bucket",
                prefixes=["syslog/"],
                log_filter="",
                start=datetime(2026, 6, 1, tzinfo=UTC),
                end=datetime(2026, 6, 30, tzinfo=UTC),
                max_records=UNLIMITED_RECORDS,
                project_scope=["p1"],
            )
        )

    assert [r["insertId"] for r in out] == ["keep"]
    # The 2025 object was pruned by its /YYYY/MM/DD/ path without being downloaded.
    assert downloaded == ["syslog/2026/06/15/00:00_a.json"]
