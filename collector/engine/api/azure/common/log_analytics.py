"""Collect diagnostic logs from Log Analytics workspaces (LA-only routing)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common import window_bounds
from .log_analytics_common import (
    CATEGORY_TO_SOURCE,
    DEFAULT_WINDOW_DAYS,
    LA_SOURCE_SPECS,
    MAX_RECORDS,
    PERMISSION_NOTE,
)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _kql(categories: list[str], start: datetime, end: datetime, *, limit: int) -> str:
    cats = ", ".join(f"'{c}'" for c in sorted(set(categories)))
    return (
        "union isfuzzy=true AzureDiagnostics, StorageBlobLogs "
        f"| where TimeGenerated between (datetime({_iso(start)}) .. datetime({_iso(end)})) "
        f"| where Category in ({cats}) "
        f"| order by TimeGenerated asc "
        f"| take {limit}"
    )


def _tag_record(rec: dict[str, Any], *, workspace_id: str) -> dict[str, Any]:
    tagged = dict(rec)
    category = str(rec.get("Category") or rec.get("category") or "")
    tagged["_ventra_la_workspace"] = workspace_id
    tagged["_ventra_la_source"] = CATEGORY_TO_SOURCE.get(category, "log_analytics")
    tagged["_ventra_resource_id"] = str(
        rec.get("ResourceId") or rec.get("_ResourceId") or rec.get("resourceId") or ""
    )
    return tagged


def collect_log_analytics(collector) -> SourceResult:
    cf = collector.ctx.client_factory
    name = collector.name
    gaps: list[tuple[str, GapReason, str]] = []
    cap = collector.max_records(MAX_RECORDS)
    start, end = window_bounds(collector.ctx.time_window, DEFAULT_WINDOW_DAYS)

    # workspace ARM id → categories enabled via diagnostic settings on in-scope resources
    workspaces: dict[str, set[str]] = {}
    resource_hits = 0
    la_only_hits = 0

    for source_id, spec in LA_SOURCE_SPECS.items():
        for sub in collector.ctx.subscription_ids:
            try:
                resources = cf.resources_of_type(sub, spec["resource_types"])
            except AzureAccessDenied as exc:
                gaps.append((name, GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
                continue
            except AzureServiceNotEnabled:
                continue
            for res in resources:
                resource_hits += 1
                try:
                    settings = cf.diagnostic_settings(res["id"])
                except AzureAccessDenied as exc:
                    gaps.append((name, GapReason.ACCESS_DENIED, f"{res['name']}: {exc.message}"))
                    continue
                except AzureServiceNotEnabled:
                    settings = []
                wanted = {c.lower() for c in spec["categories"]}
                for setting in settings:
                    ws = setting.get("workspace_id") or ""
                    if not ws:
                        continue
                    enabled = [
                        c for c in (setting.get("categories") or [])
                        if c.lower() in wanted
                    ]
                    if not enabled:
                        continue
                    la_only_hits += 1
                    workspaces.setdefault(ws, set()).update(enabled)

    if resource_hits == 0 and not gaps:
        gaps.append((name, GapReason.NOT_PRESENT, "No diagnostic-settings-backed resources in scope."))
    elif not workspaces:
        gaps.append(
            (
                name,
                GapReason.LOGGING_NOT_CONFIGURED,
                "No resources route enabled log categories to a Log Analytics workspace.",
            )
        )

    records: list[dict[str, Any]] = []
    per_workspace: list[dict[str, Any]] = []
    truncated = False

    for workspace_id, categories in sorted(workspaces.items()):
        if len(records) >= cap:
            truncated = True
            break
        remaining = cap - len(records)
        query = _kql(sorted(categories), start, end, limit=remaining)
        try:
            rows = cf.log_analytics_query(workspace_id, query, max_records=remaining)
        except AzureAccessDenied as exc:
            gaps.append(
                (name, GapReason.ACCESS_DENIED, f"{workspace_id}: {exc.message} {PERMISSION_NOTE}")
            )
            continue
        except AzureServiceNotEnabled as exc:
            gaps.append((name, GapReason.NOT_PRESENT, f"{workspace_id}: {exc.message}"))
            continue
        tagged = [_tag_record(r, workspace_id=workspace_id) for r in rows]
        records.extend(tagged)
        per_workspace.append(
            {"workspace_id": workspace_id, "records": len(tagged), "categories": sorted(categories)}
        )
        if len(records) >= cap:
            truncated = True

    if truncated:
        gaps.append(
            (
                name,
                GapReason.COLLECTOR_ERROR,
                f"Truncated at {cap:,} Log Analytics records — narrow --since/--until.",
            )
        )

    files = []
    if records:
        files.append(collector.write_jsonl(records, "events.jsonl.gz"))
    collector.write_meta(
        {
            "source": name,
            "records": len(records),
            "workspaces_queried": len(per_workspace),
            "la_routed_resources": la_only_hits,
            "window": collector.ctx.time_window.to_manifest(),
            "workspaces": per_workspace,
            "truncated": truncated,
        }
    )

    status = SourceStatus.EMPTY
    if records:
        status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
    return SourceResult(
        name=name,
        status=status,
        files=files,
        record_count=len(records),
        gaps=gaps,
        notes=(
            f"{len(records)} Log Analytics record(s) from {len(per_workspace)} workspace(s) "
            f"({DEFAULT_WINDOW_DAYS}d default window)."
        ),
    )
