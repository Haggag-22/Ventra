"""Collect diagnostic logs from Log Analytics workspaces (LA-only routing)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from collector.lib.limits import records_unlimited
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window, param_strings
from collector.lib.scoping import filter_azure_resources, matches_any
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
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
    artifact_params = collector.artifact_params()
    start, end = effective_window(collector.ctx, name, default_days=DEFAULT_WINDOW_DAYS)
    workspace_filter = param_strings(artifact_params, "workspace_ids")

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
                res_list = filter_azure_resources([res], artifact_params)
                if not res_list:
                    continue
                res = res_list[0]
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

    record_count = 0
    per_workspace: list[dict[str, Any]] = []
    truncated = False
    files = []

    with collector.open_jsonl("events.jsonl.gz") as writer:
        for workspace_id, categories in sorted(workspaces.items()):
            if workspace_filter and not matches_any(workspace_id, workspace_filter):
                continue
            if not records_unlimited(cap) and record_count >= cap:
                truncated = True
                break
            remaining = cap - record_count if not records_unlimited(cap) else cap
            query = _kql(sorted(categories), start, end, limit=remaining)
            before = record_count
            try:
                for row in cf.log_analytics_query(workspace_id, query, max_records=remaining):
                    writer.write_record(_tag_record(row, workspace_id=workspace_id))
                    record_count += 1
                    if not records_unlimited(cap) and record_count >= cap:
                        truncated = True
                        break
            except AzureAccessDenied as exc:
                gaps.append(
                    (name, GapReason.ACCESS_DENIED, f"{workspace_id}: {exc.message} {PERMISSION_NOTE}")
                )
                record_count = before
                continue
            except AzureServiceNotEnabled as exc:
                gaps.append((name, GapReason.NOT_PRESENT, f"{workspace_id}: {exc.message}"))
                record_count = before
                continue
            per_workspace.append(
                {
                    "workspace_id": workspace_id,
                    "records": record_count - before,
                    "categories": sorted(categories),
                }
            )
        if writer.count:
            files.append(writer.finalize())

    if truncated:
        collector.append_truncation_gap(
            gaps,
            name,
            cap,
            f"Truncated at {cap:,} Log Analytics records — narrow --since/--until.",
        )
    collector.write_meta(
        {
            "source": name,
            "records": record_count,
            "workspaces_queried": len(per_workspace),
            "la_routed_resources": la_only_hits,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": artifact_params,
            "workspaces": per_workspace,
            "truncated": truncated,
        }
    )

    status = SourceStatus.EMPTY
    if record_count:
        status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
    return SourceResult(
        name=name,
        status=status,
        files=files,
        record_count=record_count,
        gaps=gaps,
        notes=(
            f"{record_count} Log Analytics record(s) from {len(per_workspace)} workspace(s) "
            f"({DEFAULT_WINDOW_DAYS}d default window)."
        ),
    )
