"""Base class for collectors that pull records from Cloud Logging."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from collector.lib.base import Collector
from collector.lib.limits import records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus, TimeWindow
from collector.lib.params import effective_window, param_int, param_raw, param_strings
from collector.lib.scoping import gcp_logging_filter_extension
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

DEFAULT_WINDOW_DAYS = 90
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS


def window_bounds(tw: TimeWindow, default_days: int = DEFAULT_WINDOW_DAYS) -> tuple[datetime, datetime]:
    end = tw.until or datetime.now(UTC)
    start = tw.since or (end - timedelta(days=default_days))
    return start, end


class GcpLoggingCollector(Collector):
    """Query Cloud Logging across in-scope projects with a shared filter pattern."""

    log_filter: str = ""
    default_window_days: int = DEFAULT_WINDOW_DAYS

    def _window(self) -> tuple[datetime, datetime]:
        default_days = param_int(self.artifact_params(), "window_days", default=self.default_window_days)
        return effective_window(
            self.ctx,
            self.name,
            default_days=default_days or self.default_window_days,
        )

    def _combined_log_filter(self) -> str:
        base = self.log_filter.strip()
        params = self.artifact_params()
        service_names = param_strings(params, "service_names")
        method_names = param_strings(params, "method_names")
        extra_parts: list[str] = []
        if service_names:
            inner = " OR ".join(f'protoPayload.serviceName="{s}"' for s in service_names)
            extra_parts.append(f"({inner})")
        if method_names:
            inner = " OR ".join(f'protoPayload.methodName="{m}"' for m in method_names)
            extra_parts.append(f"({inner})")
        scoped = gcp_logging_filter_extension(params)
        if scoped:
            extra_parts.append(scoped)
        if not extra_parts:
            return base
        joined = " AND ".join(extra_parts)
        return f"({base}) AND ({joined})" if base else joined

    def _cap(self) -> int:
        return self.max_records(MAX_RECORDS)

    def _projects(self) -> list[str]:
        params = self.artifact_params()
        audit_project = param_raw(params, "audit_project_id")
        if isinstance(audit_project, str) and audit_project.strip():
            return [audit_project.strip()]
        return self.ctx.project_ids

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        projects = self._projects()
        if not projects:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.NOT_PRESENT, "No projects in scope.")],
                notes="No projects discovered or specified.",
            )

        start, end = self._window()
        log_filter = self._combined_log_filter()
        cap = self._cap()
        per_project: list[dict[str, Any]] = []
        truncated = False
        record_count = 0

        with self.open_jsonl("events.jsonl.gz") as writer:
            for project_id in projects:
                if not records_unlimited(cap) and record_count >= cap:
                    truncated = True
                    break
                before = record_count
                try:
                    remaining = cap - record_count if not records_unlimited(cap) else cap
                    for entry in cf.list_log_entries(
                        project_id,
                        log_filter=log_filter,
                        start=start,
                        end=end,
                        max_records=remaining,
                    ):
                        tagged = dict(entry)
                        tagged["_ventra_project_id"] = project_id
                        writer.write_record(tagged)
                        record_count += 1
                        if not records_unlimited(cap) and record_count >= cap:
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
                        "records": record_count - before,
                        "window_start": start.isoformat(),
                        "window_end": end.isoformat(),
                    }
                )

        if truncated:
            self.append_truncation_gap(
                gaps,
                self.name,
                cap,
                f"Truncated at {cap:,} records; narrow the window or use enterprise profile.",
            )

        files = [
            self.write_json(
                {
                    "projects": per_project,
                    "log_filter": log_filter,
                    "artifact_parameters": self.artifact_params(),
                },
                "config.json",
            )
        ]
        if record_count:
            files.append(writer.finalize())

        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "projects": per_project,
                "truncated": truncated,
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if (gaps or truncated) else SourceStatus.COLLECTED
            notes = f"{record_count} log record(s) across {len(projects)} project(s)."
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
            record_count=record_count,
            gaps=gaps,
            notes=notes,
        )
