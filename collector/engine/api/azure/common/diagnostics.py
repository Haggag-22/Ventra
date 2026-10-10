"""Generic collector for resource logs routed via a diagnostic setting to a Storage account.

Most Azure resource logs (firewall, App Gateway/WAF, Front Door, DNS, Key Vault, SQL audit…)
only exist if a **diagnostic setting** routes them somewhere. This helper:

  1. discovers every resource of the given type(s),
  2. reads its diagnostic setting to find where logs go,
  3. reads the matching JSON blobs from the **Storage** destination and ships them raw, and
  4. records a Log-Coverage **gap** when a resource has no diagnostic setting, or routes its
     logs only to Log Analytics / Event Hub (which this Storage reader can't pull).

Collectors stay thin (just declare resource types + log categories); the per-source field
mapping lives in the normalizers, matching the rest of the codebase.
"""

from __future__ import annotations

from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import scoped_window
from collector.lib.scoping import filter_azure_resources, filter_storage_access_records

from .storage_logs import read_log_records, resource_id_prefixes


def _container_for(category: str) -> str:
    return f"insights-logs-{category.lower()}"


def _enabled_categories(setting: dict, wanted: set[str]) -> list[str]:
    """Categories this diagnostic setting actually delivers, including an allLogs group."""
    enabled = [c for c in (setting.get("categories") or []) if str(c).lower() in wanted]
    groups = {str(g).lower() for g in (setting.get("category_groups") or [])}
    if "alllogs" in groups:
        seen = {str(c).lower() for c in enabled}
        enabled.extend(c for c in wanted if c not in seen)
    return enabled


def collect_diagnostic_logs(
    collector,
    *,
    resource_types: list[str],
    log_categories: list[str],
    default_window_days: int = 7,
    name_param: str = "resource_ids",
    post_filter: bool = False,
    diagnostic_resource_suffixes: list[str] | None = None,
) -> SourceResult:
    cf = collector.ctx.client_factory
    name = collector.name
    params = collector.artifact_params()
    wanted = {c.lower() for c in log_categories}
    gaps: list[tuple[str, GapReason, str]] = []
    records: list[dict] = []
    per_resource: list[dict] = []
    resource_count = 0
    start, end = scoped_window(collector.ctx, name, default_days=default_window_days)

    for sub in collector.ctx.subscription_ids:
        try:
            resources = cf.resources_of_type(sub, resource_types)
        except AzureAccessDenied as exc:
            gaps.append((name, GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
            continue
        except AzureServiceNotEnabled:
            continue
        resources = filter_azure_resources(resources, params, name_param=name_param)
        for res in resources:
            resource_count += 1
            rid = res["id"]
            diagnostic_ids = (
                [f"{rid}{suffix}" for suffix in diagnostic_resource_suffixes]
                if diagnostic_resource_suffixes
                else [rid]
            )
            settings = []
            settings_denied = False
            for diagnostic_id in diagnostic_ids:
                try:
                    settings.extend(cf.diagnostic_settings(diagnostic_id))
                except AzureAccessDenied as exc:
                    gaps.append((name, GapReason.ACCESS_DENIED, f"{res['name']}: {exc.message}"))
                    settings_denied = True
                    break
                except AzureServiceNotEnabled:
                    continue
            if settings_denied:
                continue

            if not settings:
                gaps.append(
                    (
                        name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        f"{res['name']}: no diagnostic setting — logging blind spot.",
                    )
                )
                continue

            storage_cats = [
                (s["storage_account_id"], c)
                for s in settings
                if s.get("storage_account_id")
                for c in _enabled_categories(s, wanted)
            ]
            if not storage_cats:
                gaps.append(
                    (
                        name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        f"{res['name']}: logs not routed to a Storage account "
                        "(Log Analytics / Event Hub only) — not collectible via Storage.",
                    )
                )
                continue

            before = len(records)
            for storage_id, category in storage_cats:
                try:
                    cc = cf.container_client(storage_id, _container_for(category))
                    for rec in read_log_records(cc, prefixes=resource_id_prefixes(rid), start=start, end=end):
                        rec["_ventra_resource_id"] = rid
                        records.append(rec)
                except AzureAccessDenied as exc:
                    gaps.append((name, GapReason.ACCESS_DENIED, f"{res['name']}: {exc.message}"))
                except AzureServiceNotEnabled:
                    pass
            per_resource.append({"resource": rid, "records": len(records) - before})

    if post_filter:
        records = filter_storage_access_records(records, params)

    if resource_count == 0 and not any(g[1] == GapReason.ACCESS_DENIED for g in gaps):
        gaps.append((name, GapReason.NOT_PRESENT, "No resources of this type in scope."))

    files = []
    if records:
        files.append(collector.write_jsonl(records, "events.jsonl.gz"))
    collector.write_meta(
        {
            "source": name,
            "records": len(records),
            "resources": resource_count,
            "collected": per_resource,
            "window": (
                {"since": start.isoformat(), "until": end.isoformat()}
                if start and end
                else collector.ctx.time_window.to_manifest()
            ),
            "artifact_parameters": params,
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
        notes=f"{len(records)} record(s) from {resource_count} resource(s) of type(s) {resource_types}.",
    )
