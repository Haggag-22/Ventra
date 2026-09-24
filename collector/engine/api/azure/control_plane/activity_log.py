"""Azure Activity Log collector."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from collector.lib.base import Collector
from collector.lib.limits import records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import arm_activity_log_filter
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
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
        cap = self.max_records(MAX_RECORDS)
        artifact_params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)

        subscriptions = self.ctx.subscription_ids
        if not subscriptions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("activity_log", GapReason.NOT_PRESENT, "No subscriptions in scope.")],
                notes="No subscriptions discovered or specified.",
            )

        record_count = 0
        per_sub: list[dict[str, Any]] = []
        truncated = False
        files = []

        for sub in subscriptions:
            if not records_unlimited(cap) and record_count >= cap:
                truncated = True
                break
            sub_count_before = record_count
            sub_truncated = False
            chunks = _chunk_slices(start, end, days=CHUNK_DAYS)
            fname = f"events-{_safe_sub_filename(sub)}.jsonl.gz"
            try:
                with self.open_jsonl(fname) as writer:
                    for chunk_start, chunk_end in chunks:
                        if not records_unlimited(cap) and record_count >= cap:
                            sub_truncated = True
                            truncated = True
                            break
                        filter_str = arm_activity_log_filter(artifact_params, chunk_start, chunk_end)
                        remaining = cap - record_count if not records_unlimited(cap) else cap
                        for ev in cf.activity_log_events(sub, filter_str, max_records=remaining):
                            tagged = dict(ev)
                            tagged.setdefault("subscriptionId", sub)
                            tagged["_ventra_subscription_id"] = sub
                            writer.write_record(tagged)
                            record_count += 1
                            if not records_unlimited(cap) and record_count >= cap:
                                sub_truncated = True
                                truncated = True
                                break
                    if writer.count:
                        files.append(writer.finalize())
            except AzureAccessDenied as exc:
                gaps.append(
                    ("activity_log", GapReason.ACCESS_DENIED, f"{sub}: {exc.message} {PERMISSION_NOTE}")
                )
                record_count = sub_count_before
                continue
            except AzureServiceNotEnabled as exc:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, f"{sub}: {exc.message}"))
                record_count = sub_count_before
                continue

            per_sub.append(
                {
                    "subscription_id": sub,
                    "records": record_count - sub_count_before,
                    "chunks": len(chunks),
                    "truncated": sub_truncated,
                }
            )

        if truncated:
            self.append_truncation_gap(
                gaps,
                "activity_log",
                cap,
                f"Collection stopped at {cap:,} records — data may be truncated. "
                "Narrow --since/--until or use --subscription for one subscription at a time.",
            )

        self.write_meta(
            {
                "source": self.name,
                "records": record_count,
                "subscriptions": per_sub,
                "truncated": truncated,
                "chunk_days": CHUNK_DAYS,
                "default_window_days": DEFAULT_WINDOW_DAYS,
                "retention_note": RETENTION_NOTE,
                "permission_note": PERMISSION_NOTE,
                "window": {"since": start.isoformat(), "until": end.isoformat()},
                "artifact_parameters": artifact_params,
                "invictus_parity": "Get-ActivityLogs: 89d default, all/--subscription, date range",
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, "No Activity Log events in window."))

        notes = (
            f"{record_count} Activity Log event(s) across {len(subscriptions)} subscription(s) "
            f"({CHUNK_DAYS}d chunks, {DEFAULT_WINDOW_DAYS}d default window)."
        )
        if truncated:
            notes += f" Truncated at {cap:,} records."
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=record_count,
            gaps=gaps,
            notes=notes,
        )
