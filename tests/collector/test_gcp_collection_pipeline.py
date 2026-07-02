"""GCP collection pipeline tests — dedup, shared reads, resolution skips, summary.

All GCP calls are mocked; these run the real runner + collectors + client-factory routing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from collector.clouds.gcp.client_factory import GcpClientFactory, GcpIdentity, _RateLimiter
from collector.engine.api.gcp import runner as runner_mod
from collector.engine.api.gcp.runner import GcpRunConfig, run_gcp_collection
from collector.engine.gcp_strategy_resolver import (
    STATUS_BIGQUERY,
    STATUS_NOT_COLLECTED,
    CollectorResolution,
)
from collector.lib.models import TimeWindow

WINDOW = TimeWindow(
    since=datetime(2026, 6, 1, tzinfo=UTC),
    until=datetime(2026, 6, 30, tzinfo=UTC),
)
BQ_BACKEND = {"mode": "bigquery", "bigquery": {"dataset": "demo.logs"}}


def _fake_factory(projects: tuple[str, ...] = ("demo",)) -> GcpClientFactory:
    cf = object.__new__(GcpClientFactory)
    cf._credentials = object()
    cf._default_project = projects[0]
    cf._logging_clients = {}
    cf._log_throttle = _RateLimiter(1_000_000)
    cf.caller_identity = lambda: GcpIdentity(project_id=projects[0], principal="sa@test")
    cf.projects = lambda explicit=None: list(explicit or projects)
    return cf


def _cfg(tmp_path: Path, collectors: list[str], **overrides) -> GcpRunConfig:
    defaults = dict(
        case_id="CASE-PIPE",
        collectors=collectors,
        regions=None,
        project_id="demo",
        time_window=WINDOW,
        out_dir=tmp_path / "out",
        gcp_log_backend=dict(BQ_BACKEND),
    )
    defaults.update(overrides)
    return GcpRunConfig(**defaults)


def _resolution(cid: str, status: str = STATUS_BIGQUERY, reason: str | None = None,
                tables: list[str] | None = None) -> CollectorResolution:
    return CollectorResolution(
        collector_id=cid,
        collector_name=cid,
        status=status,
        strategy_used="bigquery" if status == STATUS_BIGQUERY else "none",
        reason=reason,
        table_or_prefix=None,
        has_service_filter=False,
        service_filter=None,
        tables=tables or [],
    )


def _da_row(service: str, insert_id: str, project: str = "demo") -> dict:
    return {
        "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access",
        "insertId": insert_id,
        "timestamp": "2026-06-15T10:00:00Z",
        "protoPayload": {"serviceName": service},
        "resource": {"type": "audited_resource", "labels": {}},
    }


def _patch_resolver(monkeypatch, resolutions_by_id):
    def fake_resolve(selected, strategy, target="", project_id="", **kw):
        return [resolutions_by_id[c] for c in selected if c in resolutions_by_id]

    monkeypatch.setattr(runner_mod, "resolve_collection_strategy", fake_resolve)


def _patch_bq_reader(monkeypatch, rows: list[dict]):
    calls: list[dict] = []

    def fake_iter(*, credentials, project_id, dataset, tables, log_filter, start, end,
                  max_records, read_all_tables=False, project_scope=None, stats=None):
        calls.append(
            {
                "collector_tables": list(tables),
                "log_filter": log_filter,
                "start": start,
                "end": end,
                "project_scope": list(project_scope or []),
            }
        )
        if stats is not None:
            stats.setdefault("tables_read", []).extend(tables)
        yield from (dict(r) for r in rows)

    monkeypatch.setattr("collector.engine.gcp_log_export.iter_bigquery_log_entries", fake_iter)
    return calls


def _capture_summary(monkeypatch) -> dict:
    captured: dict = {}
    real = runner_mod.write_collection_summary

    def wrapper(staging, summary):
        captured.update(summary)
        return real(staging, summary)

    monkeypatch.setattr(runner_mod, "write_collection_summary", wrapper)
    return captured


def _outcome(summary: dict, collector: str) -> dict:
    return next(c for c in summary["collectors"] if c["collector"] == collector)


def test_broad_plus_subset_collected_once(monkeypatch, tmp_path) -> None:
    """Dedup rule: a serviceName view selected alongside its broad stream never triggers a
    second read — the broad stream is collected once and the view is reported through it."""
    rows = [_da_row("storage.googleapis.com", "s1"), _da_row("bigquery.googleapis.com", "b1")]
    calls = _patch_bq_reader(monkeypatch, rows)
    _patch_resolver(
        monkeypatch,
        {
            "cloud_audit_data": _resolution(
                "cloud_audit_data", tables=["cloudaudit_googleapis_com_data_access"]
            )
        },
    )
    summary = _capture_summary(monkeypatch)

    run_gcp_collection(
        _cfg(tmp_path, ["cloud_audit_data", "storage_access"]), factory=_fake_factory()
    )

    assert len(calls) == 1  # single read of the shared table — no per-view re-query
    broad = _outcome(summary, "cloud_audit_data")
    assert broad["status"] == "collected"
    assert broad["records"] == 2
    subset = _outcome(summary, "storage_access")
    assert subset["status"] == "collected"
    assert subset["collected_via"] == "cloud_audit_data"


def test_subsets_without_broad_share_one_spooled_read(monkeypatch, tmp_path) -> None:
    """Two views of one shared table (broad stream unselected) fill a single spooled read
    and fan out in memory — each still writes its own filtered evidence file."""
    rows = [_da_row("storage.googleapis.com", "s1"), _da_row("bigquery.googleapis.com", "b1")]
    calls = _patch_bq_reader(monkeypatch, rows)
    _patch_resolver(
        monkeypatch,
        {
            "storage_access": _resolution("storage_access"),
            "bigquery_audit": _resolution("bigquery_audit"),
        },
    )
    summary = _capture_summary(monkeypatch)

    run_gcp_collection(
        _cfg(tmp_path, ["storage_access", "bigquery_audit"]), factory=_fake_factory()
    )

    assert len(calls) == 1  # the shared table was read once, with the broad group filter
    assert "cloudaudit.googleapis.com%2Fdata_access" in calls[0]["log_filter"]
    storage = _outcome(summary, "storage_access")
    bigquery = _outcome(summary, "bigquery_audit")
    assert storage["status"] == "collected" and storage["records"] == 1
    assert bigquery["status"] == "collected" and bigquery["records"] == 1


def test_not_collected_resolution_skips_collector_with_reason(monkeypatch, tmp_path) -> None:
    reason = "No sink routing 'compute.googleapis.com/vpc_flows' to this dataset."
    calls = _patch_bq_reader(monkeypatch, [])
    _patch_resolver(
        monkeypatch,
        {"vpc_flow": _resolution("vpc_flow", status=STATUS_NOT_COLLECTED, reason=reason)},
    )
    summary = _capture_summary(monkeypatch)

    run_gcp_collection(_cfg(tmp_path, ["vpc_flow"]), factory=_fake_factory())

    assert calls == []  # never queried — NOT_COLLECTED is explicit, not silently empty
    outcome = _outcome(summary, "vpc_flow")
    assert outcome["status"] == "not_collected"
    assert outcome["reason"] == reason
    assert summary["totals"] == {
        "selected": 1,
        "collected": 0,
        "not_collected": 1,
        "records": 0,
    }


def test_multiple_projects_share_one_qualified_dataset_read(monkeypatch, tmp_path) -> None:
    """A fully-qualified dataset holds every project's rows: one read, scoped to the
    selected project IDs, rows attributed to their owning project."""
    rows = [
        {
            "logName": f"projects/{p}/logs/cloudaudit.googleapis.com%2Factivity",
            "insertId": f"{p}-1",
            "timestamp": "2026-06-15T10:00:00Z",
            "resource": {"type": "global", "labels": {}},
        }
        for p in ("p1", "p2")
    ]
    calls = _patch_bq_reader(monkeypatch, rows)
    _patch_resolver(monkeypatch, {"cloud_audit_admin": _resolution("cloud_audit_admin")})
    summary = _capture_summary(monkeypatch)

    run_gcp_collection(
        _cfg(tmp_path, ["cloud_audit_admin"], project_id="p1,p2"),
        factory=_fake_factory(("p1", "p2")),
    )

    assert len(calls) == 1  # not one identical full-table scan per project
    assert calls[0]["project_scope"] == ["p1", "p2"]
    assert calls[0]["start"] == WINDOW.since and calls[0]["end"] == WINDOW.until
    assert _outcome(summary, "cloud_audit_admin")["records"] == 2
    assert summary["projects"] == ["p1", "p2"]


def test_log_explorer_queries_every_project_with_window(tmp_path) -> None:
    """Logging API strategy: each project is queried, and every query carries the
    Since/Until window in its filter."""

    class FakeLoggingClient:
        def __init__(self) -> None:
            self.filters: list[str] = []

        def list_entries(self, *, filter_, order_by, page_size, max_results):
            self.filters.append(filter_)
            yield SimpleNamespace(
                to_api_repr=lambda: {
                    "insertId": "x",
                    "timestamp": "2026-06-15T10:00:00Z",
                    "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
                }
            )

    clients = {"p1": FakeLoggingClient(), "p2": FakeLoggingClient()}
    cf = _fake_factory(("p1", "p2"))
    cf._logging_clients = dict(clients)

    run_gcp_collection(
        _cfg(
            tmp_path,
            ["cloud_audit_admin"],
            project_id="p1,p2",
            gcp_log_backend={"mode": "logging_api"},
        ),
        factory=cf,
    )

    for client in clients.values():
        assert len(client.filters) == 1
        assert 'timestamp >= "2026-06-01T00:00:00Z"' in client.filters[0]
        assert 'timestamp <= "2026-06-30T00:00:00Z"' in client.filters[0]
