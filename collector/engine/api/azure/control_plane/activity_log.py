"""Azure Activity Log collector.

The Activity Log is the Azure equivalent of CloudTrail management events: subscription-scoped
control-plane operations — who created/modified/deleted which resource, from which IP, with
what outcome. Pulled per in-scope subscription via the Monitor management API.

Invictus parity: default 89-day window, all subscriptions (or ``--subscription``), optional
``--since`` / ``--until``. Ventra also writes per-subscription event files and queries in
7-day chunks to improve completeness on busy tenants.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import arm_time_filter, window_bounds
from .activity_log_common import (
    CHUNK_DAYS,
    DEFAULT_WINDOW_DAYS,
    MAX_RECORDS,
    PERMISSION_NOTE,
    RETENTION_NOTE,
)


def _chunk_slices(start: datetime, end: datetime, *, days: int) -> list[tuple[datetime, datetime]]:
    slices: list[tuple[datetime, datetime]] = []
    cur = start
    step = timedelta(days=days)
    while cur < end:
        nxt = min(cur + step, end)
        slices.append((cur, nxt))
        cur = nxt
    return slices


def _safe_sub_filename(subscription_id: str) -> str:
    return subscription_id.replace("/", "_")


class ActivityLogCollector(Collector):
    name = "activity_log"
    priority = 1
    description = (
        "Azure Activity Log — subscription control-plane operations (Monitor API, 89d default)."
    )
    required_actions = ("Microsoft.Insights/eventtypes/values/read",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        start, end = window_bounds(self.ctx.time_window, DEFAULT_WINDOW_DAYS)

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
        truncated = False
        files = []

        for sub in subscriptions:
            if len(records) >= MAX_RECORDS:
                truncated = True
                break
            sub_records: list[dict[str, Any]] = []
            sub_truncated = False
            chunks = _chunk_slices(start, end, days=CHUNK_DAYS)
            try:
                for chunk_start, chunk_end in chunks:
                    if len(records) >= MAX_RECORDS:
                        sub_truncated = True
                        truncated = True
                        break
                    filter_str = arm_time_filter(chunk_start, chunk_end)
                    remaining = MAX_RECORDS - len(records)
                    for ev in cf.activity_log_events(sub, filter_str, max_records=remaining):
                        tagged = dict(ev)
                        tagged.setdefault("subscriptionId", sub)
                        tagged["_ventra_subscription_id"] = sub
                        sub_records.append(tagged)
                        records.append(tagged)
                        if len(records) >= MAX_RECORDS:
                            sub_truncated = True
                            truncated = True
                            break
            except AzureAccessDenied as exc:
                gaps.append(
                    ("activity_log", GapReason.ACCESS_DENIED, f"{sub}: {exc.message} {PERMISSION_NOTE}")
                )
                continue
            except AzureServiceNotEnabled as exc:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, f"{sub}: {exc.message}"))
                continue

            if sub_records:
                fname = f"events-{_safe_sub_filename(sub)}.jsonl.gz"
                files.append(self.write_jsonl(sub_records, fname))
            per_sub.append(
                {
                    "subscription_id": sub,
                    "records": len(sub_records),
                    "chunks": len(chunks),
                    "truncated": sub_truncated,
                }
            )

        if records:
            files.insert(0, self.write_jsonl(records, "events.jsonl.gz"))

        if truncated:
            gaps.append(
                (
                    "activity_log",
                    GapReason.NOT_PRESENT,
                    f"Collection stopped at {MAX_RECORDS:,} records — data may be truncated. "
                    "Narrow --since/--until or use --subscription for one subscription at a time.",
                )
            )

        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "subscriptions": per_sub,
                "truncated": truncated,
                "chunk_days": CHUNK_DAYS,
                "default_window_days": DEFAULT_WINDOW_DAYS,
                "retention_note": RETENTION_NOTE,
                "permission_note": PERMISSION_NOTE,
                "window": self.ctx.time_window.to_manifest(),
                "invictus_parity": "Get-ActivityLogs: 89d default, all/--subscription, date range",
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, "No Activity Log events in window."))

        notes = (
            f"{len(records)} Activity Log event(s) across {len(subscriptions)} subscription(s) "
            f"({CHUNK_DAYS}d chunks, {DEFAULT_WINDOW_DAYS}d default window)."
        )
        if truncated:
            notes += f" Truncated at {MAX_RECORDS:,} records."
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=notes,
        )
