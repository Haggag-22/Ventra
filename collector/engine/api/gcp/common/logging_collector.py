"""Base class for collectors that pull records from Cloud Logging."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus, TimeWindow
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

DEFAULT_WINDOW_DAYS = 90
MAX_RECORDS = 200_000


def window_bounds(tw: TimeWindow, default_days: int = DEFAULT_WINDOW_DAYS) -> tuple[datetime, datetime]:
    end = tw.until or datetime.now(UTC)
    start = tw.since or (end - timedelta(days=default_days))
    return start, end


def _parse_relative_since(value: str, end: datetime) -> datetime | None:
    """Parse artifact parameter values like ``30d`` into an absolute start time."""
    val = value.strip().lower()
    if val.endswith("d") and val[:-1].isdigit():
        return end - timedelta(days=int(val[:-1]))
    return None


class GcpLoggingCollector(Collector):
    """Query Cloud Logging across in-scope projects with a shared filter pattern."""

    log_filter: str = ""
    default_window_days: int = DEFAULT_WINDOW_DAYS

    def _window(self) -> tuple[datetime, datetime]:
        params = self.artifact_params()
        default_days = int(params.get("window_days", self.default_window_days))
        start, end = window_bounds(self.ctx.time_window, default_days)
        rel = params.get("since")
        if isinstance(rel, str) and rel.strip():
            parsed = _parse_relative_since(rel, end)
            if parsed is not None:
                start = parsed
        return start, end

    def _cap(self) -> int:
        return self.max_records(MAX_RECORDS)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        projects = self.ctx.project_ids
        if not projects:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.NOT_PRESENT, "No projects in scope.")],
                notes="No projects discovered or specified.",
            )

        start, end = self._window()
        cap = self._cap()
        records: list[dict[str, Any]] = []
        per_project: list[dict[str, Any]] = []
        truncated = False

        for project_id in projects:
            if len(records) >= cap:
                truncated = True
                break
            before = len(records)
            try:
                for entry in cf.list_log_entries(
                    project_id,
                    log_filter=self.log_filter,
                    start=start,
                    end=end,
                    max_records=cap - len(records),
                ):
                    tagged = dict(entry)
                    tagged["_ventra_project_id"] = project_id
                    records.append(tagged)
                    if len(records) >= cap:
                        truncated = True
                        break
            except GcpAccessDenied as exc:
                gaps.append((self.name, GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))
                continue
            except GcpServiceNotEnabled as exc:
                gaps.append((self.name, GapReason.SERVICE_NOT_ENABLED, f"{project_id}: {exc.message}"))
                continue

            per_project.append(
                {
                    "project_id": project_id,
                    "records": len(records) - before,
                    "window_start": start.isoformat(),
                    "window_end": end.isoformat(),
                }
            )

        files = [self.write_json({"projects": per_project, "log_filter": self.log_filter}, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))

        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "projects": per_project,
                "truncated": truncated,
            }
        )

        if records:
            status = SourceStatus.PARTIAL if (gaps or truncated) else SourceStatus.COLLECTED
            notes = f"{len(records)} log record(s) across {len(projects)} project(s)."
            if truncated:
                notes += f" Truncated at {cap:,} records."
        else:
            status = SourceStatus.EMPTY
            notes = "No matching log entries in the time window."
            if not gaps:
                gaps.append(
                    (
                        self.name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "No log entries found — logging may not be enabled or exported.",
                    )
                )

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=notes,
        )
