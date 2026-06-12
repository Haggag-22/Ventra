"""CloudTrail log file validation via ``aws cloudtrail validate-logs``.

Uses digest files in the trail S3 bucket to verify S3-resident logs were not tampered with
before the collector reads event files. Requires the AWS CLI (present in CloudShell).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ...lib.models import GapReason

_RATIO_RE = re.compile(
    r"(\d+)/(\d+)\s+(digest|log)\s+files\s+(valid|INVALID)",
    re.IGNORECASE,
)
_INVALID_LINE_RE = re.compile(r"\tINVALID:", re.IGNORECASE)


@dataclass
class TrailValidationResult:
    trail_arn: str
    trail_name: str
    status: str  # valid | invalid | skipped | error
    skip_reason: str = ""
    digest_valid: int = 0
    digest_total: int = 0
    digest_invalid: int = 0
    log_valid: int = 0
    log_total: int = 0
    log_invalid: int = 0
    invalid_details: list[str] = field(default_factory=list)
    stdout_excerpt: str = ""
    exit_code: int | None = None

    @property
    def passed(self) -> bool:
        return self.status == "valid"

    def to_dict(self) -> dict[str, Any]:
        return {
            "trail_arn": self.trail_arn,
            "trail_name": self.trail_name,
            "status": self.status,
            "skip_reason": self.skip_reason,
            "digest_valid": self.digest_valid,
            "digest_total": self.digest_total,
            "digest_invalid": self.digest_invalid,
            "log_valid": self.log_valid,
            "log_total": self.log_total,
            "log_invalid": self.log_invalid,
            "invalid_details": self.invalid_details[:50],
            "exit_code": self.exit_code,
        }


def format_cli_time(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%SZ")


def parse_validation_output(output: str, result: TrailValidationResult) -> None:
    """Parse ``aws cloudtrail validate-logs`` stdout/stderr into counts and detail lines."""
    for line in output.splitlines():
        if _INVALID_LINE_RE.search(line):
            result.invalid_details.append(line.strip())
        for match in _RATIO_RE.finditer(line):
            count, total, kind, outcome = match.groups()
            n, t = int(count), int(total)
            is_digest = kind.lower() == "digest"
            if outcome.lower() == "valid":
                if is_digest:
                    result.digest_valid = max(result.digest_valid, n)
                    result.digest_total = max(result.digest_total, t)
                else:
                    result.log_valid = max(result.log_valid, n)
                    result.log_total = max(result.log_total, t)
            else:
                if is_digest:
                    result.digest_invalid = max(result.digest_invalid, n)
                    result.digest_total = max(result.digest_total, t)
                else:
                    result.log_invalid = max(result.log_invalid, n)
                    result.log_total = max(result.log_total, t)

    if result.digest_total and not result.digest_valid and not result.digest_invalid:
        result.digest_valid = result.digest_total
    if result.log_total and not result.log_valid and not result.log_invalid:
        result.log_valid = result.log_total


def validate_trail_logs(
    trail: dict[str, Any],
    account_id: str,
    start: datetime,
    end: datetime,
    *,
    aws_binary: str | None = None,
    timeout_seconds: int = 600,
) -> TrailValidationResult:
    """Run AWS CLI log validation for one trail over ``start``..``end`` (UTC)."""
    arn = str(trail.get("TrailARN") or "")
    name = str(trail.get("Name") or arn.rsplit("/", 1)[-1])
    result = TrailValidationResult(trail_arn=arn, trail_name=name, status="skipped")

    if not trail.get("LogFileValidationEnabled"):
        result.skip_reason = "log_file_validation_not_enabled"
        return result

    if not trail.get("S3BucketName"):
        result.skip_reason = "no_s3_bucket"
        return result

    status = trail.get("Status") or {}
    if not status.get("IsLogging"):
        result.skip_reason = "trail_not_logging"
        return result

    aws = aws_binary or shutil.which("aws")
    if not aws:
        result.status = "error"
        result.skip_reason = "aws_cli_not_found"
        return result

    home = str(trail.get("HomeRegion") or (arn.split(":")[3] if arn else "us-east-1"))
    cmd = [
        aws,
        "cloudtrail",
        "validate-logs",
        "--trail-arn",
        arn,
        "--start-time",
        format_cli_time(start),
        "--end-time",
        format_cli_time(end),
        "--no-cli-pager",
        "--region",
        home,
    ]
    if trail.get("IsOrganizationTrail"):
        cmd.extend(["--account-id", account_id])
    bucket = trail.get("S3BucketName")
    prefix = (trail.get("S3KeyPrefix") or "").strip()
    if bucket:
        cmd.extend(["--s3-bucket", str(bucket)])
    if prefix:
        cmd.extend(["--s3-prefix", prefix])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result.status = "error"
        result.skip_reason = "validation_timeout"
        return result
    except OSError as exc:
        result.status = "error"
        result.skip_reason = str(exc)
        return result

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    result.stdout_excerpt = output.strip()[-4000:]
    result.exit_code = proc.returncode
    parse_validation_output(output, result)

    if result.digest_invalid > 0 or result.log_invalid > 0 or result.invalid_details:
        result.status = "invalid"
    elif proc.returncode != 0 and result.digest_total == 0 and result.log_total == 0:
        result.status = "error"
        result.skip_reason = result.skip_reason or "validate_logs_failed"
    elif result.digest_total > 0 or result.log_total > 0 or proc.returncode == 0:
        result.status = "valid"
    else:
        result.status = "error"
        result.skip_reason = result.skip_reason or "validate_logs_failed"

    return result


def validation_gaps(
    results: list[TrailValidationResult],
) -> list[tuple[str, GapReason, str]]:
    """Turn failed validations into manifest gaps (tampering is a forensic finding)."""
    gaps: list[tuple[str, GapReason, str]] = []
    for res in results:
        if res.status == "invalid":
            parts = []
            if res.digest_invalid:
                parts.append(f"{res.digest_invalid}/{res.digest_total} digest files INVALID")
            if res.log_invalid:
                parts.append(f"{res.log_invalid}/{res.log_total} log files INVALID")
            detail = "; ".join(parts) or "validate-logs reported integrity failures"
            if res.invalid_details:
                detail += f" — e.g. {res.invalid_details[0][:200]}"
            gaps.append((f"log_validation:{res.trail_name}", GapReason.LOG_INTEGRITY_FAILED, detail))
        elif res.status == "error" and res.skip_reason not in (
            "aws_cli_not_found",
        ):
            gaps.append(
                (
                    f"log_validation:{res.trail_name}",
                    GapReason.COLLECTOR_ERROR,
                    f"Log validation error: {res.skip_reason or 'validate-logs failed'}",
                )
            )
    return gaps
