"""Azure Activity Log collector — control-plane write operations (reads not logged by default)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, AzureClientFactory


class ActivityLogCollector(Collector):
    name = "activity_log"
    priority = 1
    description = "Azure Activity Log — subscription control-plane operations."
    required_actions = (
        "Microsoft.Insights/ActivityLogs/read",
        "Microsoft.Insights/DiagnosticSettings/read",
    )

    def collect(self) -> SourceResult:
        cf: AzureClientFactory = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        window = self.ctx.time_window
        end = window.until or datetime.now(UTC)
        start = window.since or (end - timedelta(days=90))

        config = {
            "note": (
                "Azure Activity Log records write/control-plane operations by default. "
                "Read operations are not logged unless explicitly configured — "
                "document as a visibility gap when absent."
            ),
            "window": window.to_manifest(),
        }

        try:
            records = cf.list_activity_logs(since=start, until=end)
        except AccessDenied as exc:
            gaps.append(("activity_log", GapReason.ACCESS_DENIED, exc.message))
            records = []
        except Exception as exc:
            gaps.append(("activity_log", GapReason.COLLECTOR_ERROR, str(exc)))
            records = []

        files = [self.write_json(config, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {"source": self.name, "records": len(records), "window": window.to_manifest()}
        )

        if not records and not gaps:
            gaps.append(
                (
                    "activity_log",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "No Activity Log events in the requested window.",
                )
            )

        status = SourceStatus.COLLECTED if records else SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} activity log event(s).",
        )
