"""Tests for Cloud Logging entry serialization in the GCP client factory."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as gcp_exc

from collector.clouds.gcp import client_factory as cf_mod
from collector.clouds.gcp.client_factory import (
    _LOG_PAGE_SIZE,
    GcpClientFactory,
    GcpRateLimited,
    _entry_to_dict,
    _enum_name,
    _mapping_to_dict,
    _RateLimiter,
)


def test_enum_name_accepts_string_or_enum() -> None:
    assert _enum_name("INFO") == "INFO"
    assert _enum_name(SimpleNamespace(name="WARNING")) == "WARNING"
    assert _enum_name(None) == ""


def test_mapping_to_dict_handles_none() -> None:
    assert _mapping_to_dict(None) == {}


def test_entry_to_dict_prefers_to_api_repr() -> None:
    entry = SimpleNamespace(
        to_api_repr=lambda: {
            "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
            "severity": "INFO",
            "protoPayload": {"methodName": "google.api.method"},
        }
    )
    out = _entry_to_dict(entry)
    assert out["logName"].endswith("activity")
    assert out["protoPayload"]["methodName"] == "google.api.method"


def test_entry_to_dict_string_severity_and_none_labels() -> None:
    entry = SimpleNamespace(
        log_name="projects/p/logs/cloudaudit.googleapis.com%2Factivity",
        timestamp=None,
        severity="INFO",
        insert_id="abc123",
        resource=SimpleNamespace(type="global", labels=None),
        labels=None,
        payload=None,
        proto_payload=None,
        text_payload="hello",
        json_payload=None,
    )
    out = _entry_to_dict(entry)
    assert out["severity"] == "INFO"
    assert out["resource"]["labels"] == {}
    assert out["labels"] == {}
    assert out["textPayload"] == "hello"


def test_entry_to_dict_json_payload_mapping() -> None:
    entry = SimpleNamespace(
        log_name="projects/p/logs/compute.googleapis.com%2Frequests",
        timestamp=None,
        severity=SimpleNamespace(name="DEFAULT"),
        insert_id="id1",
        resource=SimpleNamespace(type="http_load_balancer", labels={"url_map_name": "web"}),
        labels={"key": "value"},
        payload=None,
        proto_payload=None,
        text_payload=None,
        json_payload={"cacheLookup": True, "cacheHit": False},
    )
    out = _entry_to_dict(entry)
    assert out["jsonPayload"] == {"cacheLookup": True, "cacheHit": False}
    assert out["resource"]["labels"]["url_map_name"] == "web"


# -- Rate limiting / 429 backoff -----------------------------------------------------------


def _entry(insert_id: str, ts: str) -> SimpleNamespace:
    return SimpleNamespace(to_api_repr=lambda i=insert_id, t=ts: {"insertId": i, "timestamp": t})


def _factory_with_client(client: object) -> GcpClientFactory:
    """A factory wired to a fake logging client, bypassing ADC auth in __init__."""
    cf = object.__new__(GcpClientFactory)
    cf._logging_clients = {"proj": client}
    cf._log_throttle = _RateLimiter(1_000_000)  # effectively no pacing for the test
    return cf


def _window() -> dict[str, object]:
    return {
        "log_filter": 'logName="x"',
        "start": datetime(2026, 6, 1, tzinfo=UTC),
        "end": datetime(2026, 6, 30, tzinfo=UTC),
    }


def test_list_log_entries_pulls_full_pages_and_caps() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.page_sizes: list[int] = []

        def list_entries(self, *, filter_, order_by, page_size, max_results):
            self.page_sizes.append(page_size)
            for n in range(5):
                yield _entry(f"id{n}", f"2026-06-15T10:00:0{n}.000Z")

    client = FakeClient()
    cf = _factory_with_client(client)
    out = list(cf.list_log_entries("proj", max_records=3, **_window()))

    assert [r["insertId"] for r in out] == ["id0", "id1", "id2"]  # capped at max_records
    assert client.page_sizes == [_LOG_PAGE_SIZE]  # asks for the largest page → fewest reads


def test_list_log_entries_resumes_after_429_without_duplicates(monkeypatch) -> None:
    monkeypatch.setattr(cf_mod, "_sleep_backoff", lambda attempt: 0.0)

    class FlakyClient:
        def __init__(self) -> None:
            self.filters: list[str] = []

        def list_entries(self, *, filter_, order_by, page_size, max_results):
            self.filters.append(filter_)
            if len(self.filters) == 1:
                yield _entry("a", "2026-06-30T10:00:05.000Z")
                yield _entry("b", "2026-06-30T10:00:03.000Z")
                raise gcp_exc.ResourceExhausted("429 quota exceeded")
            # Retry re-queries the tightened window (<= 10:00:03) and re-sees b.
            yield _entry("b", "2026-06-30T10:00:03.000Z")
            yield _entry("c", "2026-06-30T10:00:01.000Z")

    client = FlakyClient()
    cf = _factory_with_client(client)
    out = list(cf.list_log_entries("proj", max_records=100, **_window()))

    assert [r["insertId"] for r in out] == ["a", "b", "c"]  # b not duplicated
    assert 'timestamp <= "2026-06-30T10:00:03Z"' in client.filters[1]  # window tightened on resume


def test_list_log_entries_stays_patient_while_making_progress(monkeypatch) -> None:
    # Each retry yields one more entry then 429s — far more times than any fixed retry budget.
    # Because the scan keeps making progress, patience never runs out and every entry is collected.
    monkeypatch.setattr(cf_mod, "_sleep_backoff", lambda attempt: 0.0)

    total = 10

    class SlowDripClient:
        def __init__(self) -> None:
            self.calls = 0

        def list_entries(self, *, filter_, order_by, page_size, max_results):
            idx = self.calls
            self.calls += 1
            yield _entry(f"id{idx}", f"2026-06-30T10:00:{59 - idx:02d}.000Z")
            if idx < total - 1:
                raise gcp_exc.ResourceExhausted("429 quota exceeded")

    client = SlowDripClient()
    cf = _factory_with_client(client)
    out = list(cf.list_log_entries("proj", max_records=100, **_window()))

    assert [r["insertId"] for r in out] == [f"id{i}" for i in range(total)]
    assert client.calls == total  # never gave up despite 9 consecutive 429s


def test_list_log_entries_gives_up_only_after_long_stall(monkeypatch) -> None:
    # No progress at all: patience is bounded by the stall limit, then it raises GcpRateLimited.
    monkeypatch.setattr(cf_mod, "_sleep_backoff", lambda attempt: 100.0)
    monkeypatch.setenv("VENTRA_GCP_LOG_STALL_LIMIT_S", "250")

    class AlwaysExhausted:
        def __init__(self) -> None:
            self.calls = 0

        def list_entries(self, *, filter_, order_by, page_size, max_results):
            self.calls += 1
            raise gcp_exc.ResourceExhausted("429 quota exceeded")
            yield  # pragma: no cover — makes this a generator

    client = AlwaysExhausted()
    cf = _factory_with_client(client)
    with pytest.raises(GcpRateLimited):
        list(cf.list_log_entries("proj", max_records=100, **_window()))
    assert client.calls == 4  # stall reaches 300s (>=250) only on the 4th attempt


def test_rate_limiter_blocks_when_tokens_exhausted(monkeypatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(cf_mod.time, "sleep", lambda s: slept.append(s))

    limiter = _RateLimiter(60)  # 1 token/sec
    limiter._tokens = 0.0
    limiter._updated = cf_mod.time.monotonic()
    limiter.acquire()

    assert slept and 0.5 < slept[0] <= 1.0  # waited ~1s for a token rather than exceeding quota


def test_list_log_entries_unlimited_returns_every_entry() -> None:
    """Records field empty (Unlimited): the full multi-page stream is returned, and no
    ceiling below the sentinel is passed to the API."""
    from collector.lib.limits import UNLIMITED_RECORDS

    total = 2_500  # spans multiple 1000-entry API pages

    class FakeClient:
        def __init__(self) -> None:
            self.max_results: list[int] = []

        def list_entries(self, *, filter_, order_by, page_size, max_results):
            self.max_results.append(max_results)
            for n in range(total):
                yield _entry(f"id{n}", f"2026-06-15T10:{n // 100:02d}:{n % 60:02d}.000Z")

    client = FakeClient()
    cf = _factory_with_client(client)
    out = list(cf.list_log_entries("proj", max_records=UNLIMITED_RECORDS, **_window()))

    assert len(out) == total
    assert client.max_results == [UNLIMITED_RECORDS]
