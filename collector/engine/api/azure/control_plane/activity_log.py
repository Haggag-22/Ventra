"""Azure Activity Log collector."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from collector.lib.base import Collector
from collector.lib.limits import records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import arm_activity_log_filter

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
    description = "Azure Activity Log — Monitor API or a subscription diagnostic storage archive."
    required_actions = ("Microsoft.Insights/eventtypes/values/read",)

    def collect(self) -> SourceResult:
        from collector.engine.azure_log_backend import AzureLogBackendSpec

        spec = AzureLogBackendSpec.from_dict(getattr(self.ctx, "azure_log_backend", None))
        if spec.uses_storage():
            return self._collect_from_storage()
        return self._collect_from_api()

    def _collect_from_storage(self) -> SourceResult:
        """Read Activity Log blobs named by each subscription's diagnostic setting."""
        from collector.engine.api.azure.common.diagnostics import _container_for, _enabled_categories
        from collector.engine.api.azure.common.storage_logs import read_log_records, resource_id_prefixes
        from collector.engine.azure_log_backend import ACTIVITY_LOG_STORAGE_CATEGORIES

        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        cap = self.max_records(MAX_RECORDS)
        artifact_params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        wanted = {c.lower() for c in ACTIVITY_LOG_STORAGE_CATEGORIES}

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
            rid = f"/subscriptions/{sub}"
            sub_count_before = record_count
            fname = f"events-{_safe_sub_filename(sub)}.jsonl.gz"
            try:
                settings = cf.diagnostic_settings(rid)
            except AzureAccessDenied as exc:
                gaps.append(("activity_log", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
                continue
            except AzureServiceNotEnabled as exc:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, f"{sub}: {exc.message}"))
                continue

            if not settings:
                gaps.append(
                    (
                        "activity_log",
                        GapReason.LOGGING_NOT_CONFIGURED,
                        f"{sub}: no subscription diagnostic setting — Activity Log is not archived to Storage.",
                    )
                )
                continue

            storage_cats = [
                (s["storage_account_id"], c)
                for s in settings
                if s.get("storage_account_id")
                for c in _enabled_categories(s, wanted)
            ]
            seen: set[tuple[str, str]] = set()
            destinations = []
            for storage_id, category in storage_cats:
                key = (str(storage_id).lower(), category.lower())
                if key in seen:
                    continue
                seen.add(key)
                destinations.append((storage_id, category))

            if not destinations:
                gaps.append(
                    (
                        "activity_log",
                        GapReason.LOGGING_NOT_CONFIGURED,
                        f"{sub}: Activity Log is not routed to a Storage account "
                        "(Log Analytics / Event Hub only).",
                    )
                )
                continue

            try:
                with self.open_jsonl(fname) as writer:
                    for storage_id, category in destinations:
                        if not records_unlimited(cap) and record_count >= cap:
                            truncated = True
                            break
                        remaining = cap - record_count if not records_unlimited(cap) else cap
                        try:
                            cc = cf.container_client(storage_id, _container_for(category))
                            for rec in read_log_records(
                                cc,
                                prefixes=resource_id_prefixes(rid),
                                start=start,
                                end=end,
                                max_records=remaining,
                            ):
                                tagged = dict(rec)
                                tagged.setdefault("subscriptionId", sub)
                                tagged["_ventra_subscription_id"] = sub
                                tagged["_ventra_activity_category"] = category
                                writer.write_record(tagged)
                                record_count += 1
                                if not records_unlimited(cap) and record_count >= cap:
                                    truncated = True
                                    break
                        except AzureAccessDenied as exc:
                            gaps.append(("activity_log", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
                        except AzureServiceNotEnabled:
                            continue
                    if writer.count:
                        files.append(writer.finalize())
            except AzureAccessDenied as exc:
                gaps.append(("activity_log", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
                record_count = sub_count_before
                continue

            per_sub.append(
                {
                    "subscription_id": sub,
                    "records": record_count - sub_count_before,
                    "destinations": len(destinations),
                    "truncated": truncated,
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
                "mode": "storage",
                "records": record_count,
                "subscriptions": per_sub,
                "truncated": truncated,
                "window": {"since": start.isoformat(), "until": end.isoformat()},
                "artifact_parameters": artifact_params,
            }
        )

        if record_count:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append(("activity_log", GapReason.NOT_PRESENT, "No Activity Log blobs in window."))

        notes = (
            f"{record_count} Activity Log event(s) from storage across {len(subscriptions)} subscription(s)."
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

    def _collect_from_api(self) -> SourceResult:
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
                "mode": "monitor_api",
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
