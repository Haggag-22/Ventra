"""Unit tests for CloudTrail log file validation helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from collector.engine.api.aws.control_plane.cloudtrail_validation import (
    TrailValidationResult,
    format_cli_time,
    parse_validation_output,
    validate_trail_logs,
    validation_gaps,
)
from collector.lib.models import GapReason


def test_format_cli_time() -> None:
    dt = datetime(2026, 6, 1, 12, 30, 45, tzinfo=UTC)
    assert format_cli_time(dt) == "20260601T123045Z"


def test_parse_validation_output_valid() -> None:
    result = TrailValidationResult(trail_arn="arn", trail_name="t1", status="skipped")
    parse_validation_output(
        """
        Results found for 2026-06-01T00:00:00Z to 2026-06-02T00:00:00Z:
        3/3 digest files valid
        15/15 log files valid
        """,
        result,
    )
    assert result.digest_valid == 3
    assert result.digest_total == 3
    assert result.log_valid == 15
    assert result.log_total == 15


def test_parse_validation_output_invalid_lines() -> None:
    result = TrailValidationResult(trail_arn="arn", trail_name="t1", status="skipped")
    parse_validation_output(
        """
        2/3 digest files valid, 1/3 digest files INVALID
        14/15 log files valid, 1/15 log files INVALID
        Log file\ts3://bucket/key\tINVALID: hash value doesn't match
        """,
        result,
    )
    assert result.digest_invalid == 1
    assert result.digest_total == 3
    assert result.log_invalid == 1
    assert result.log_total == 15
    assert len(result.invalid_details) == 1


def test_validation_gaps_on_integrity_failure() -> None:
    res = TrailValidationResult(
        trail_arn="arn",
        trail_name="prod",
        status="invalid",
        digest_invalid=1,
        digest_total=3,
        log_invalid=2,
        log_total=10,
    )
    gaps = validation_gaps([res])
    assert len(gaps) == 1
    assert gaps[0][1] == GapReason.LOG_INTEGRITY_FAILED
    assert "digest" in gaps[0][2]


def test_validate_trail_logs_skips_when_not_enabled() -> None:
    trail = {"TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/x", "Name": "x"}
    res = validate_trail_logs(
        trail,
        "1",
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 2, tzinfo=UTC),
    )
    assert res.status == "skipped"
    assert res.skip_reason == "log_file_validation_not_enabled"


def test_validate_trail_logs_runs_cli_when_enabled() -> None:
    trail = {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/prod",
        "Name": "prod",
        "HomeRegion": "us-east-1",
        "S3BucketName": "my-trail-bucket",
        "LogFileValidationEnabled": True,
        "Status": {"IsLogging": True},
    }
    cli_stdout = "3/3 digest files valid\n15/15 log files valid\n"

    class FakeProc:
        returncode = 0
        stdout = cli_stdout
        stderr = ""

    with patch(
        "collector.engine.api.aws.control_plane.cloudtrail_validation.subprocess.run",
        return_value=FakeProc(),
    ) as run:
        res = validate_trail_logs(
            trail,
            "123456789012",
            datetime(2026, 6, 1, tzinfo=UTC),
            datetime(2026, 6, 2, tzinfo=UTC),
            aws_binary="/usr/bin/aws",
        )

    assert res.status == "valid"
    assert res.digest_valid == 3
    assert res.log_valid == 15
    cmd = run.call_args[0][0]
    assert cmd[0] == "/usr/bin/aws"
    assert "validate-logs" in cmd
    assert "--trail-arn" in cmd
