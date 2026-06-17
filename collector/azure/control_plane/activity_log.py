"""Azure Activity Log collector.

The Activity Log is the Azure equivalent of CloudTrail management events: subscription-scoped
control-plane operations — who created/modified/deleted which resource, from which IP, with
what outcome. Pulled per in-scope subscription via the Monitor management API.

Unlike CloudTrail, the Activity Log is always on and queryable for ~90 days without any
diagnostic setting, so this is a management-API collector (no diagnostic-settings dependency).
"""

from __future__ import annotations

from typing import Any

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import arm_time_filter, window_bounds

# The Activity Log retains ~90 days.
DEFAULT_WINDOW_DAYS = 90
MAX_RECORDS = 200_000


class ActivityLogCollector(Collector):
    name = "activity_log"
    priority = 1
    description = "Azure Activity Log — subscription control-plane operations (Monitor API)."
    required_actions = ("Microsoft.Insights/eventtypes/values/read",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)
        filter_str = arm_time_filter(start, end)

        subscriptions = self.ctx.subscription_ids
        if not subscriptions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("activity_log", GapReason.NOT_PRESENT, "No subscriptions in scope.")],
                notes="No subscriptions discovered or specified.",
            )

        records: list[dict[str, Any]] = []
        per_sub: list[dict[str, Any]] = []
        for sub in subscriptions:
            before = len(records)
            try:
                for ev in cf.activity_log_events(sub, filter_str, max_records=MAX_RECORDS):
                    records.append(ev)
            except AzureAccessDenied as exc:
                gaps.append(("activity_log", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, f"{sub}: {exc.message}"))
            per_sub.append({"subscription_id": sub, "records": len(records) - before})

        files = []
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "subscriptions": per_sub,
                "window": self.ctx.time_window.to_manifest(),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, "No Activity Log events in window."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} Activity Log event(s) across {len(subscriptions)} subscription(s).",
        )
