"""Base class for collectors that pull records from Cloud Logging."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Iterator

from collector.lib.base import Collector
from collector.lib.limits import records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus, TimeWindow
from collector.lib.params import logging_window, param_int, param_raw, param_strings
from collector.lib.scoping import gcp_logging_filter_extension
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpRateLimited, GcpServiceNotEnabled

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

    def _window(self) -> tuple[datetime | None, datetime | None]:
        default_days = param_int(self.artifact_params(), "window_days", default=self.default_window_days)
        return logging_window(
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
        regions = self._regions_clause()
        if regions:
            extra_parts.append(regions)
        if not extra_parts:
            return base
        joined = " AND ".join(extra_parts)
        return f"({base}) AND ({joined})" if base else joined

    def _regions_clause(self) -> str:
        """Global Regions scope from the run config, when the analyst set one.

        GCP log entries carry the region under different labels per resource type, so a
        region matches ``region``/``location`` exactly or ``zone`` as a prefix.
        """
        regions = [r.strip() for r in (self.ctx.regions or []) if r and r.strip()]
        if not regions:
            return ""
        parts = []
        for region in regions:
            parts.append(
                f'resource.labels.region="{region}" OR '
                f'resource.labels.location="{region}" OR '
                f'resource.labels.zone:"{region}"'
            )
        return f"({' OR '.join(parts)})"

    def _cap(self) -> int:
        return self.max_records(MAX_RECORDS)

    def _projects(self) -> list[str]:
        params = self.artifact_params()
        audit_project = param_raw(params, "audit_project_id")
        if isinstance(audit_project, str) and audit_project.strip():
            return [audit_project.strip()]
        return self.ctx.project_ids

    def _iter_log_entries(
        self,
        cf: Any,
        project_id: str,
        *,
        log_filter: str,
        start: datetime,
        end: datetime,
        max_records: int,
    ) -> Iterator[dict[str, Any]]:
        backend = getattr(self.ctx, "gcp_log_backend", {}) or {}
        return cf.list_log_entries_for_backend(
            project_id,
            collector=self.name,
            log_filter=log_filter,
            start=start,
            end=end,
            max_records=max_records,
            gcp_log_backend=backend,
            artifact_params=self.artifact_params(),
        )

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
        backend = getattr(self.ctx, "gcp_log_backend", {}) or {}
        backend_mode = str(backend.get("mode") or "logging_api")
        read_stats: dict[str, Any] = {}

        with self.open_jsonl("events.jsonl.gz") as writer:
            if backend_mode == "gcs":
                # Export backends read each distinct dataset/bucket once for all projects —
                # re-reading per project would duplicate evidence. Rows are scoped to the
                # in-scope projects and attributed to their owner from logName.
                counts: dict[str, int] = {}
                try:
                    for owner, entry in cf.iter_log_entries_all_projects(
                        projects,
                        collector=self.name,
                        log_filter=log_filter,
                        start=start,
                        end=end,
                        max_records=cap,
                        gcp_log_backend=backend,
                        artifact_params=self.artifact_params(),
                        stats=read_stats,
                    ):
                        tagged = dict(entry)
                        tagged["_ventra_project_id"] = owner
                        writer.write_record(tagged)
                        counts[owner] = counts.get(owner, 0) + 1
                        record_count += 1
                        if not records_unlimited(cap) and record_count >= cap:
                            truncated = True
                            break
                except GcpAccessDenied as exc:
                    gaps.append((self.name, GapReason.ACCESS_DENIED, exc.message))
                except GcpServiceNotEnabled as exc:
                    gaps.append((self.name, GapReason.SERVICE_NOT_ENABLED, exc.message))
                except GcpRateLimited as exc:
                    gaps.append((self.name, GapReason.RATE_LIMITED, exc.message))
                for project_id in projects:
                    per_project.append(
                        {
                            "project_id": project_id,
                            "records": counts.pop(project_id, 0),
                            "window_start": start.isoformat() if start is not None else None,
                            "window_end": end.isoformat() if end is not None else None,
                        }
                    )
                for owner, n in counts.items():  # rows owned by folders/orgs or aliases
                    per_project.append({"project_id": owner, "records": n})
            else:
                for project_id in projects:
                    if not records_unlimited(cap) and record_count >= cap:
                        truncated = True
                        break
                    before = record_count
                    try:
                        remaining = cap - record_count if not records_unlimited(cap) else cap
                        for entry in self._iter_log_entries(
                            cf,
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
                        gaps.append(
                            (self.name, GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}")
                        )
                        continue
                    except GcpServiceNotEnabled as exc:
                        gaps.append(
                            (self.name, GapReason.SERVICE_NOT_ENABLED, f"{project_id}: {exc.message}")
                        )
                        continue
                    except GcpRateLimited as exc:
                        gaps.append(
                            (self.name, GapReason.RATE_LIMITED, f"{project_id}: {exc.message}")
                        )
                        continue

                    per_project.append(
                        {
                            "project_id": project_id,
                            "records": record_count - before,
                            "window_start": start.isoformat() if start is not None else None,
                            "window_end": end.isoformat() if end is not None else None,
                        }
                    )

        if truncated:
            self.append_truncation_gap(
                gaps,
                self.name,
                cap,
                f"Truncated at {cap:,} records; narrow the window or use enterprise profile.",
            )

        excluded_ts = int(read_stats.get("excluded_unparseable_timestamp", 0) or 0)
        if excluded_ts:
            gaps.append(
                (
                    self.name,
                    GapReason.UNPARSEABLE_TIMESTAMP,
                    f"{excluded_ts:,} record(s) excluded from the export: unparseable or missing "
                    "timestamp cannot be confirmed within the requested window.",
                )
            )

        config: dict[str, Any] = {
            "projects": per_project,
            "log_filter": log_filter,
            "gcp_log_backend_mode": backend_mode,
            "artifact_parameters": self.artifact_params(),
        }
        if read_stats:
            config["tables_read"] = read_stats.get("tables_read", [])
            config["rows_by_table"] = read_stats.get("rows_by_table", {})
        files = [self.write_json(config, "config.json")]
        if record_count:
            files.append(writer.finalize())

        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "projects": per_project,
                "truncated": truncated,
                "gcp_log_backend_mode": backend_mode,
                "tables_read": read_stats.get("tables_read", []),
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if (gaps or truncated) else SourceStatus.COLLECTED
            notes = f"{record_count} log record(s) across {len(projects)} project(s)."
            if truncated:
                notes += f" Truncated at {cap:,} records."
        else:
            status = SourceStatus.EMPTY
            notes = (
                "No matching log entries in the configured window."
                if start is not None or end is not None
                else "No matching log entries found."
            )
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
