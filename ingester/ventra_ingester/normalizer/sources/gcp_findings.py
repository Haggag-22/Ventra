"""Security Command Center findings → unified events."""

from __future__ import annotations

from typing import Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_SCC_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


@register("scc_findings")
def normalize_scc_findings(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for f in records:
        sev = str(f.get("severity") or f.get("finding", {}).get("severity") or "MEDIUM").upper()
        category = f.get("category") or f.get("findingClass") or "scc_finding"
        name = f.get("name") or f.get("parent") or ""
        org = f.get("_ventra_organization_id") or ctx.account_id
        yield UnifiedEvent(
            timestamp=f.get("eventTime") or f.get("createTime") or "",
            event_kind="finding",
            event_category=["finding"],
            event_action=category,
            event_outcome="failure",
            event_severity=_SCC_SEVERITY.get(sev, "medium"),
            event_provider="security_command_center",
            cloud_provider="gcp",
            cloud_account=org,
            cloud_service="securitycenter",
            resource_id=name,
            resource_arn=name,
            related_resource=[name] if name else [],
            message=f.get("description") or f.get("sourceProperties", {}).get("Explanation", category),
            case_id=ctx.case_id,
            ventra_source="scc_findings",
            raw=f,
        )
