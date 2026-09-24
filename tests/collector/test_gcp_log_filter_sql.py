"""Equivalence + fallback tests for the DuckDB log-filter fast path.

The contract is: DuckDB filtering must select *exactly* the same rows, in the same order, as the
reference Python ``matches_gcp_log_filter`` / ``entry_in_window`` / ``entry_in_project_scope``
loop. These tests prove that over the real Ventra filter set plus edge-case entry shapes, and
verify the Python fallback triggers (disabled flag, untranslatable atom, runtime DuckDB error).
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime

import pytest

from collector.engine import gcp_strategy_resolver as resolver
from collector.engine.gcp_log_backend import _SHARED_GROUP_FILTERS
from collector.engine.gcp_log_export import (
    UnrecognizedFilterAtom,
    entry_in_project_scope,
    entry_in_window,
    matches_gcp_log_filter,
    normalize_log_entry,
)
from collector.engine.gcp_log_filter_sql import (
    FilterTranslationError,
    GcpEntryMatcher,
    build_entry_where,
    duckdb_filter_raw_entries,
    filter_to_sql,
    replay_spool_with_fallback,
    validate_gcp_log_filter,
)

# --- corpus -------------------------------------------------------------------------------


def _corpus() -> list[dict]:
    """Raw (un-normalised) entries spanning every atom the real filters touch, plus edge shapes."""
    return [
        # 0: audit activity, ERROR severity, gce_instance with zone label
        {
            "logName": "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": "2026-01-15T12:00:00Z",
            "severity": "ERROR",
            "resource": {"type": "gce_instance", "labels": {"zone": "us-central1-a"}},
            "protoPayload": {
                "serviceName": "compute.googleapis.com",
                "methodName": "v1.compute.instances.insert",
            },
        },
        # 1: data_access for storage (snake_case aliases — exercises normalize parity)
        {
            "log_name": "projects/p1/logs/cloudaudit.googleapis.com%2Fdata_access",
            "timestamp": "2026-01-15T13:00:00Z",
            "proto_payload": {"serviceName": "storage.googleapis.com", "methodName": "storage.objects.get"},
        },
        # 2: data_access for bigquery
        {
            "logName": "projects/p2/logs/cloudaudit.googleapis.com%2Fdata_access",
            "timestamp": "2026-01-16T09:00:00Z",
            "protoPayload": {"serviceName": "bigquery.googleapis.com"},
        },
        # 3: load balancer request w/ cacheDecision present
        {
            "logName": "projects/p1/logs/requests",
            "timestamp": "2026-01-15T12:30:00Z",
            "resource": {"type": "http_load_balancer"},
            "jsonPayload": {"cacheDecision": "HIT", "enforcedSecurityPolicy": {"name": "deny-all"}},
        },
        # 4: load balancer request, cacheDecision is JSON null (presence must be FALSE)
        {
            "logName": "projects/p1/logs/requests",
            "timestamp": "2026-01-15T12:31:00Z",
            "resource": {"type": "http_load_balancer"},
            "jsonPayload": {"cacheDecision": None},
        },
        # 5: load balancer request, no jsonPayload at all
        {
            "logName": "projects/p1/logs/requests",
            "resource": {"type": "http_load_balancer"},
        },
        # 6: vpc flow (networkmanagement variant of the logName OR)
        {
            "logName": "projects/p1/logs/networkmanagement.googleapis.com%2Fvpc_flows",
            "timestamp": "2026-01-15T00:00:00Z",
            "resource": {"type": "gce_subnetwork"},
        },
        # 7: gce_instance syslog (should match the "NOT vpc_flows" vm_logs filter)
        {
            "logName": "projects/p1/logs/syslog",
            "resource": {"type": "gce_instance"},
            "severity": "WARNING",
        },
        # 8: nat gateway
        {
            "logName": "projects/p1/logs/compute.googleapis.com%2Fnat_flows",
            "resource": {"type": "nat_gateway"},
        },
        # 9: dns query
        {
            "logName": "projects/p1/logs/dns.googleapis.com%2Fdns_queries",
            "resource": {"type": "dns_query"},
        },
        # 10: gke apiserver
        {
            "logName": "projects/p2/logs/container.googleapis.com%2Fapiserver",
            "resource": {"type": "k8s_cluster"},
        },
        # 11: monitoring, NOTICE severity
        {
            "logName": "projects/p1/logs/monitoring.googleapis.com",
            "resource": {"type": "global"},
            "severity": "NOTICE",
        },
        # 12: cloudsql
        {"logName": "projects/p1/logs/z", "resource": {"type": "cloudsql_database"}},
        # 13: missing logName entirely, unparseable timestamp
        {"timestamp": "not-a-timestamp", "resource": {"type": "global"}, "severity": "CRITICAL"},
        # 14: empty-ish entry
        {"insertId": "x"},
        # 15: firewall, DEBUG
        {
            "logName": "projects/p3/logs/compute.googleapis.com%2Ffirewall",
            "resource": {"type": "gce_subnetwork"},
            "severity": "DEBUG",
        },
    ]


def _real_filters() -> list[str]:
    fs: set[str] = set()
    for v in resolver.COLLECTOR_MAP.values():
        fs.add(v["log_filter"])
    for v in _SHARED_GROUP_FILTERS.values():
        fs.add(v)
    return sorted(fs)


_EXTRA_FILTERS = [
    "",  # empty -> everything
    "severity>=WARNING",
    "severity>=ERROR",
    'resource.type="global" AND severity>=WARNING',
    'protoPayload.methodName=("storage.objects.get" OR "v1.compute.instances.insert")',
    'protoPayload.serviceName="storage.googleapis.com"',
    'resource.labels.zone="us-central1-a"',
    'resource.labels.zone:"us-central1"',
    'resource.type="gce_instance" AND NOT logName:"vpc_flows"',
    'logName:"requests" OR resource.type="dns_query"',
    # precedence: AND binds tighter than OR (matches _eval_or -> _eval_and)
    'logName:"monitoring.googleapis.com" OR resource.type="global" AND severity>=WARNING',
]

# Clauses no grammar rule recognises — both paths must now RAISE, not match-all (Task 1).
_UNKNOWN_ATOM_FILTERS = [
    'resource.tpye="x"',  # typo'd field name
    'totallyUnknownClause:"x"',
    'resource.type="gce_instance" AND unknownField="whatever"',
]


def _py_reference(entries: list[dict], f: str) -> list[dict]:
    out = []
    for raw in entries:
        e = normalize_log_entry(raw)
        if matches_gcp_log_filter(e, f):
            out.append(e)
    return out


@pytest.mark.parametrize("f", _real_filters() + _EXTRA_FILTERS)
def test_duckdb_matches_python_filter(f: str) -> None:
    corpus = _corpus()
    expected = _py_reference(corpus, f)
    got = [normalize_log_entry(e) for e in duckdb_filter_raw_entries(corpus, f)]
    assert got == expected, f"filter mismatch for {f!r}"


def test_window_and_scope_equivalence() -> None:
    corpus = _corpus()
    start = datetime(2026, 1, 15, tzinfo=UTC)
    end = datetime(2026, 1, 15, 23, 59, 59, tzinfo=UTC)
    scope = ["p1"]
    f = 'resource.type="http_load_balancer" AND logName:"requests"'

    expected = []
    for raw in corpus:
        e = normalize_log_entry(raw)
        if (
            entry_in_window(e, start, end)
            and entry_in_project_scope(e, scope)
            and matches_gcp_log_filter(e, f)
        ):
            expected.append(e)
    got = [
        normalize_log_entry(e)
        for e in duckdb_filter_raw_entries(corpus, f, start=start, end=end, project_scope=scope)
    ]
    assert got == expected


def test_empty_corpus() -> None:
    assert duckdb_filter_raw_entries([], 'logName:"x"') == []


def test_nanosecond_timestamps_under_window_match_python() -> None:
    """Cloud Logging writes nanosecond-precision UTC timestamps; DuckDB (plain TIMESTAMP, no
    pytz) must window them identically to entry_timestamp/entry_in_window (both truncate to µs)."""
    corpus = [
        {"logName": "projects/p1/logs/requests", "timestamp": "2026-01-15T12:00:00.123456789Z"},
        {"logName": "projects/p1/logs/requests", "timestamp": "2026-01-10T00:00:00.000000001Z"},  # before
        {"logName": "projects/p1/logs/requests", "timestamp": "2026-01-20T23:59:59.999999999Z"},  # after
        {"logName": "projects/p1/logs/requests", "timestamp": "2026-01-15T00:00:00Z"},  # exact start
        {"logName": "projects/p1/logs/requests"},  # no ts -> now EXCLUDED (fail-closed, Task 2)
    ]
    f = 'logName:"requests"'
    start = datetime(2026, 1, 15, tzinfo=UTC)
    end = datetime(2026, 1, 16, tzinfo=UTC)
    expected = []
    for raw in corpus:
        e = normalize_log_entry(raw)
        if (
            entry_in_window(e, start, end)
            and entry_in_project_scope(e, None)
            and matches_gcp_log_filter(e, f)
        ):
            expected.append(e)
    got = [normalize_log_entry(e) for e in duckdb_filter_raw_entries(corpus, f, start=start, end=end)]
    assert got == expected


def test_matcher_equivalence_uses_duckdb() -> None:
    corpus = _corpus()
    f = 'resource.type="http_load_balancer" AND logName:"requests"'
    m = GcpEntryMatcher(f)
    assert m.using_duckdb is True
    assert m.filter_batch(corpus) == _py_reference(corpus, f)


def test_matcher_disabled_by_env(monkeypatch) -> None:
    monkeypatch.setenv("VENTRA_GCP_DUCKDB_FILTER", "0")
    m = GcpEntryMatcher('logName:"requests"')
    assert m.using_duckdb is False
    assert m.filter_batch(_corpus()) == _py_reference(_corpus(), 'logName:"requests"')


def test_matcher_untranslatable_atom_falls_back() -> None:
    # boolean truthiness form is intentionally not translated -> Python path, same result.
    f = "jsonPayload.cacheHit=true"
    m = GcpEntryMatcher(f)
    assert m.using_duckdb is False
    assert m.filter_batch(_corpus()) == _py_reference(_corpus(), f)


def test_matcher_runtime_error_falls_back(monkeypatch) -> None:
    import collector.engine.gcp_log_filter_sql as mod

    def boom(*a, **k):
        raise RuntimeError("simulated duckdb failure")

    monkeypatch.setattr(mod, "duckdb_filter_raw_entries", boom)
    f = 'logName:"requests"'
    m = GcpEntryMatcher(f)
    assert m.using_duckdb is True  # decided translatable up front
    got = m.filter_batch(_corpus())
    assert m.using_duckdb is False  # latched to python after the failure
    assert got == _py_reference(_corpus(), f)


def test_untranslatable_atom_raises() -> None:
    with pytest.raises(FilterTranslationError):
        filter_to_sql("httpRequest.foo=true", "json", "")


def test_missing_fields_and_null_presence() -> None:
    # cacheDecision:* — present-and-not-null only (row 3 yes; row 4 null; row 5 absent)
    f = 'resource.type="http_load_balancer" AND logName:"requests" AND jsonPayload.cacheDecision:*'
    corpus = _corpus()
    got = [normalize_log_entry(e) for e in duckdb_filter_raw_entries(corpus, f)]
    assert got == _py_reference(corpus, f)
    assert len(got) == 1
    assert got[0]["jsonPayload"]["cacheDecision"] == "HIT"


# --- spool replay -------------------------------------------------------------------------


def _write_spool(tmp_path, entries: list[dict]):
    path = tmp_path / "spool.jsonl.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")
    return path


def _py_spool_reference(entries: list[dict], f: str, max_records: int, unlimited: bool) -> list[dict]:
    out = []
    for e in entries:
        if f.strip() and not matches_gcp_log_filter(e, f):
            continue
        out.append(e)
        if not unlimited and len(out) >= max_records:
            break
    return out


def test_spool_replay_equivalence(tmp_path) -> None:
    entries = [normalize_log_entry(e) for e in _corpus()]
    path = _write_spool(tmp_path, entries)
    f = 'logName:"requests"'
    got = list(replay_spool_with_fallback(path, f, max_records=0, unlimited=True))
    assert got == _py_spool_reference(entries, f, 0, True)


def test_spool_replay_max_records(tmp_path) -> None:
    entries = [normalize_log_entry(e) for e in _corpus()]
    path = _write_spool(tmp_path, entries)
    f = ""  # everything
    got = list(replay_spool_with_fallback(path, f, max_records=3, unlimited=False))
    assert got == entries[:3]


def test_spool_replay_untranslatable_falls_back(tmp_path) -> None:
    entries = [normalize_log_entry(e) for e in _corpus()]
    path = _write_spool(tmp_path, entries)
    f = "jsonPayload.cacheHit=true"  # untranslatable -> python path
    got = list(replay_spool_with_fallback(path, f, max_records=0, unlimited=True))
    assert got == _py_spool_reference(entries, f, 0, True)


def test_spool_replay_midstream_error_resumes_without_dup(tmp_path, monkeypatch) -> None:
    import collector.engine.gcp_log_filter_sql as mod

    entries = [normalize_log_entry(e) for e in _corpus()]
    path = _write_spool(tmp_path, entries)
    f = ""  # everything

    def partial_then_fail(*a, **k):
        # yield the first two rows, then blow up mid-stream
        yield entries[0]
        yield entries[1]
        raise RuntimeError("simulated mid-stream duckdb failure")

    monkeypatch.setattr(mod, "duckdb_filter_spool_file", partial_then_fail)
    got = list(replay_spool_with_fallback(path, f, max_records=0, unlimited=True))
    # No duplicates, no drops: exactly the full corpus in order.
    assert got == entries


def test_build_entry_where_is_true_for_trivial() -> None:
    assert build_entry_where("", "json", "e.") == "TRUE"


# --- Task 1: unknown filter atoms fail loud on BOTH paths --------------------------------


@pytest.mark.parametrize("f", _UNKNOWN_ATOM_FILTERS)
def test_unknown_atom_raises_on_python_path(f: str) -> None:
    # Entry satisfies the leading clause so AND-evaluation isn't short-circuited before the
    # unknown atom is reached (the deterministic guard is validate_gcp_log_filter, tested below).
    entry = {"logName": "projects/p/logs/x", "resource": {"type": "gce_instance"}}
    with pytest.raises(UnrecognizedFilterAtom):
        matches_gcp_log_filter(entry, f)


@pytest.mark.parametrize("f", _UNKNOWN_ATOM_FILTERS)
def test_unknown_atom_raises_on_duckdb_path(f: str) -> None:
    with pytest.raises(UnrecognizedFilterAtom):
        filter_to_sql(f, "json", "e.")
    with pytest.raises(UnrecognizedFilterAtom):
        build_entry_where(f, "json", "e.")


@pytest.mark.parametrize("f", _UNKNOWN_ATOM_FILTERS)
def test_unknown_atom_raises_at_validation(f: str) -> None:
    with pytest.raises(UnrecognizedFilterAtom):
        validate_gcp_log_filter(f)


@pytest.mark.parametrize("f", _UNKNOWN_ATOM_FILTERS)
def test_unknown_atom_raises_when_building_matcher(f: str) -> None:
    with pytest.raises(UnrecognizedFilterAtom):
        GcpEntryMatcher(f)


def test_unknown_atom_message_is_actionable() -> None:
    try:
        validate_gcp_log_filter('resource.tpye="x"')
    except UnrecognizedFilterAtom as exc:
        assert "resource.tpye" in str(exc)
        assert "typo" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("expected UnrecognizedFilterAtom")


@pytest.mark.parametrize("f", _real_filters() + _EXTRA_FILTERS)
def test_all_real_and_valid_filters_pass_validation(f: str) -> None:
    # Regression guard: every legitimate clause type still validates without raising.
    validate_gcp_log_filter(f)


def test_boolean_form_is_recognised_not_unknown() -> None:
    # =true/false is a *recognised* atom (just not SQL-translatable) -> must NOT raise unknown.
    validate_gcp_log_filter("jsonPayload.cacheHit=true")


# --- Task 2: unparseable/missing timestamps fail closed + counted ------------------------


def _windowed_corpus() -> list[dict]:
    return [
        {"logName": "projects/p1/logs/requests", "timestamp": "2026-01-15T12:00:00Z"},  # in
        {"logName": "projects/p1/logs/requests", "timestamp": "2026-02-20T12:00:00Z"},  # out (valid)
        {"logName": "projects/p1/logs/requests", "timestamp": "garbled-not-a-date"},  # unparseable
        {"logName": "projects/p1/logs/requests"},  # missing ts
    ]


def test_unparseable_timestamp_excluded_both_paths_and_counted() -> None:
    corpus = _windowed_corpus()
    f = 'logName:"requests"'
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 1, 31, tzinfo=UTC)

    # Python reference (fail-closed entry_in_window): only the single in-window row survives.
    expected = []
    for raw in corpus:
        e = normalize_log_entry(raw)
        if matches_gcp_log_filter(e, f) and entry_in_window(e, start, end):
            expected.append(e)
    assert len(expected) == 1

    # DuckDB path
    counters: dict[str, int] = {}
    got = [
        normalize_log_entry(e)
        for e in duckdb_filter_raw_entries(corpus, f, start=start, end=end, counters=counters)
    ]
    assert got == expected
    assert counters.get("excluded_unparseable_ts") == 2  # garbled + missing

    # Matcher (DuckDB) records the exclusion into its stats dict for gap surfacing
    stats: dict = {}
    m = GcpEntryMatcher(f, start, end, stats=stats)
    assert m.using_duckdb is True
    out = m.filter_batch(corpus)
    assert out == expected
    assert stats["excluded_unparseable_timestamp"] == 2


def test_unparseable_timestamp_excluded_python_path_and_counted(monkeypatch) -> None:
    monkeypatch.setenv("VENTRA_GCP_DUCKDB_FILTER", "0")
    corpus = _windowed_corpus()
    f = 'logName:"requests"'
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 1, 31, tzinfo=UTC)
    stats: dict = {}
    m = GcpEntryMatcher(f, start, end, stats=stats)
    assert m.using_duckdb is False
    out = m.filter_batch(corpus)
    assert len(out) == 1
    assert stats["excluded_unparseable_timestamp"] == 2


def test_no_window_keeps_unparseable_timestamp() -> None:
    # Regression: with NO window, a missing/garbled timestamp is still included (unchanged).
    assert entry_in_window({"timestamp": "garbled"}, None, None) is True
    assert entry_in_window({}, None, None) is True
    corpus = _windowed_corpus()
    stats: dict = {}
    m = GcpEntryMatcher('logName:"requests"', None, None, stats=stats)
    assert len(m.filter_batch(corpus)) == 4
    assert stats.get("excluded_unparseable_timestamp", 0) == 0


def test_entry_in_window_fail_closed_unit() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 1, 31, tzinfo=UTC)
    assert entry_in_window({"timestamp": "nope"}, start, end) is False  # was True pre-change
    assert entry_in_window({}, start, end) is False
    assert entry_in_window({"timestamp": "2026-01-15T00:00:00Z"}, start, end) is True
