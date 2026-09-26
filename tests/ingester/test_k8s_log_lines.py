"""Non-systemd node logs: the time, program and level are recovered from the line text."""

from __future__ import annotations

import pytest

from ventra_ingester.normalizer.base import NormalizeContext, normalize_source
from ventra_ingester.normalizer.sources.k8s_logs import parse_log_line

COLLECTED = "2026-09-26T07:00:00Z"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # rsyslog default (RFC 3339); offsets are converted to UTC.
        (
            "2026-09-22T22:25:54.038929+00:00 k3s-server tailscaled[1339]: magicsock: closing",
            {"timestamp": "2026-09-22T22:25:54Z", "program": "tailscaled", "message": "magicsock: closing"},
        ),
        (
            "2026-09-22T18:25:54-04:00 node k3s[812]: started",
            {"timestamp": "2026-09-22T22:25:54Z", "program": "k3s", "message": "started"},
        ),
        # BSD syslog: no year, so it takes the collection year.
        (
            "Sep 26 06:59:33 k3s-server containerd[640]: pulled image",
            {"timestamp": "2026-09-26T06:59:33Z", "program": "containerd", "message": "pulled image"},
        ),
        (
            "Sep  6 01:02:03 node rsyslogd: HUPed",
            {"timestamp": "2026-09-06T01:02:03Z", "program": "rsyslogd", "message": "HUPed"},
        ),
        # klog (kubelet.log): level letter becomes a syslog priority.
        (
            "E0926 06:59:33.123456    1234 kubelet.go:12] boom",
            {"timestamp": "2026-09-26T06:59:33Z", "priority": 3, "message": "kubelet.go:12] boom"},
        ),
    ],
)
def test_parse_log_line(line: str, expected: dict) -> None:
    parsed = parse_log_line(line, COLLECTED)
    for key, value in expected.items():
        assert parsed[key] == value


def test_yearless_line_after_collection_date_is_last_year() -> None:
    """A December line in a package collected in January belongs to the previous year."""
    parsed = parse_log_line("Dec 31 23:59:59 node cron[1]: tick", "2026-01-02T00:00:00Z")
    assert parsed["timestamp"] == "2025-12-31T23:59:59Z"


def test_unrecognised_line_parses_to_nothing() -> None:
    assert parse_log_line("not a log line") == {}


@pytest.mark.parametrize("source", ["k8s_kubelet_logs", "k8s_runtime_logs"])
def test_fallback_records_get_time_and_program(source: str) -> None:
    records = [
        {
            "MESSAGE": "2026-09-22T22:25:54.038929+00:00 k3s-server k3s[812]: Failed to pull image nginx",
            "_ventra_log_file": "/var/log/syslog",
            "_ventra_node": "k3s-server",
            "_ventra_cluster": "homelab",
        },
        {"MESSAGE": "unparseable tail line", "_ventra_log_file": "/var/log/syslog"},
    ]
    ctx = NormalizeContext(case_id="C1", account_id="homelab", collected_at=COLLECTED)
    parsed, raw_line = list(normalize_source(source, records, ctx))

    assert parsed.timestamp == "2026-09-22T22:25:54Z"
    assert parsed.event_action == "k3s"
    assert parsed.message == "Failed to pull image nginx"
    assert parsed.event_severity == "medium"  # notable-fragment escalation still applies
    assert parsed.raw["MESSAGE"].startswith("2026-09-22T22:25:54")  # evidence kept verbatim

    assert raw_line.timestamp == ""  # nothing invented for lines with no time in them
    assert raw_line.message == "unparseable tail line"


def test_journal_records_are_unchanged() -> None:
    """systemd records keep journald's own timestamp and unit; the line parser isn't used."""
    rec = {
        "__REALTIME_TIMESTAMP": "1790000000000000",
        "_SYSTEMD_UNIT": "k3s.service",
        "MESSAGE": "Sep 26 06:59:33 other-host fake[1]: looks like syslog",
    }
    ctx = NormalizeContext(case_id="C1", account_id="homelab", collected_at=COLLECTED)
    (event,) = list(normalize_source("k8s_kubelet_logs", [rec], ctx))
    assert event.timestamp == "2026-09-21T14:13:20Z"
    assert event.event_action == "k3s.service"
    assert event.message == rec["MESSAGE"]
