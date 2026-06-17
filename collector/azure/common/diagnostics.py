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

from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AzureAccessDenied, AzureServiceNotEnabled
from .storage_logs import read_log_records


def _container_for(category: str) -> str:
    return f"insights-logs-{category.lower()}"


def collect_diagnostic_logs(
    collector,
    *,
    resource_types: list[str],
    log_categories: list[str],
) -> SourceResult:
    cf = collector.ctx.client_factory
    name = collector.name
    wanted = {c.lower() for c in log_categories}
    gaps: list[tuple[str, GapReason, str]] = []
    records: list[dict] = []
    per_resource: list[dict] = []
    resource_count = 0

    for sub in collector.ctx.subscription_ids:
        try:
            resources = cf.resources_of_type(sub, resource_types)
        except AzureAccessDenied as exc:
            gaps.append((name, GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
            continue
        except AzureServiceNotEnabled:
            continue
        for res in resources:
            resource_count += 1
            rid = res["id"]
            try:
                settings = cf.diagnostic_settings(rid)
            except AzureAccessDenied as exc:
                gaps.append((name, GapReason.ACCESS_DENIED, f"{res['name']}: {exc.message}"))
                continue
            except AzureServiceNotEnabled:
                settings = []

            if not settings:
                gaps.append(
                    (name, GapReason.LOGGING_NOT_CONFIGURED,
                     f"{res['name']}: no diagnostic setting — logging blind spot.")
                )
                continue

            storage_cats = [
                (s["storage_account_id"], c)
                for s in settings
                if s.get("storage_account_id")
                for c in (s.get("categories") or [])
                if c.lower() in wanted
            ]
            if not storage_cats:
                gaps.append(
                    (name, GapReason.LOGGING_NOT_CONFIGURED,
                     f"{res['name']}: logs not routed to a Storage account "
                     "(Log Analytics / Event Hub only) — not collectible via Storage.")
                )
                continue

            before = len(records)
            for storage_id, category in storage_cats:
                try:
                    cc = cf.container_client(storage_id, _container_for(category))
                    for rec in read_log_records(cc, prefix=f"resourceId={rid.upper()}"):
                        rec["_ventra_resource_id"] = rid
                        records.append(rec)
                except AzureAccessDenied as exc:
                    gaps.append((name, GapReason.ACCESS_DENIED, f"{res['name']}: {exc.message}"))
                except AzureServiceNotEnabled:
                    pass  # container for that category may not exist yet
            per_resource.append({"resource": rid, "records": len(records) - before})

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
            "window": collector.ctx.time_window.to_manifest(),
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
