"""GuardDuty, Security Hub, Inspector2, Macie, Detective, Config normalizers → findings."""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_GD_SEVERITY = [  # GuardDuty numeric severity -> label
    (8.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (1.0, "low"),
]


def _gd_label(sev: Any) -> str:
    try:
        val = float(sev)
    except (TypeError, ValueError):
        return "info"
    for threshold, label in _GD_SEVERITY:
        if val >= threshold:
            return label
    return "info"


_SH_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}

_MACIE_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

_DETECTIVE_SEVERITY = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _securityhub_product(f: dict) -> str:
    """Return the originating product slug for an ASFF finding."""
    name = f.get("ProductName") or ""
    if not name:
        fields = f.get("ProductFields") or {}
        name = fields.get("aws/securityhub/ProductName", "")
    if name:
        return str(name).lower().replace(" ", "")
    generator = f.get("GeneratorId", "")
    if generator.startswith("aws-"):
        return generator.split("/")[0].replace("aws-", "", 1)
    return "securityhub"


def _macie_severity(f: dict) -> str:
    sev = f.get("severity")
    if isinstance(sev, dict):
        label = str(sev.get("description", "")).upper()
    else:
        label = str(sev or "").upper()
    return _MACIE_SEVERITY.get(label, "info")


@register("guardduty")
def normalize_guardduty(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for f in records:
        service = f.get("Service", {}) or {}
        action = service.get("Action", {}) or {}
        remote = (
            action.get("AwsApiCallAction", {}).get("RemoteIpDetails", {})
            or action.get("NetworkConnectionAction", {}).get("RemoteIpDetails", {})
            or {}
        )
        ip = remote.get("IpAddressV4", "")
        resource = f.get("Resource", {}) or {}
        access_key = (resource.get("AccessKeyDetails", {}) or {})
        user = access_key.get("UserName", "") or access_key.get("PrincipalId", "")
        yield UnifiedEvent(
            timestamp=f.get("UpdatedAt", f.get("CreatedAt", "")),
            event_kind="finding",
            event_category=["threat"],
            event_action=f.get("Type", ""),
            event_outcome="unknown",
            event_severity=_gd_label(f.get("Severity")),
            event_provider="guardduty",
            cloud_account=f.get("AccountId", ctx.account_id),
            cloud_region=f.get("Region", f.get("_ventra_region", "")),
            cloud_service="guardduty",
            user_name=user,
            source_ip=ip,
            source_country=(remote.get("Country", {}) or {}).get("CountryName", ""),
            source_asn=str((remote.get("Organization", {}) or {}).get("Asn", "")),
            resource_type=resource.get("ResourceType", ""),
            related_ip=[ip] if ip else [],
            related_user=[user] if user else [],
            message=f.get("Title", f.get("Type", "GuardDuty finding")),
            case_id=ctx.case_id,
            ventra_source="guardduty",
            raw=f,
        )


@register("securityhub")
def normalize_securityhub(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for f in records:
        sev = (f.get("Severity", {}) or {}).get("Label", "INFORMATIONAL")
        resources = f.get("Resources", []) or []
        res_id = resources[0].get("Id", "") if resources else ""
        product = _securityhub_product(f)
        yield UnifiedEvent(
            timestamp=f.get("UpdatedAt", f.get("CreatedAt", "")),
            event_kind="finding",
            event_category=["threat"],
            event_action=f.get("Types", [""])[0] if f.get("Types") else f.get("GeneratorId", ""),
            event_severity=_SH_SEVERITY.get(sev, "info"),
            event_provider=product,
            cloud_account=f.get("AwsAccountId", ctx.account_id),
            cloud_region=f.get("Region", f.get("_ventra_region", "")),
            cloud_service=product,
            resource_id=res_id.split("/")[-1] if res_id else "",
            resource_arn=res_id,
            related_resource=[r.get("Id", "") for r in resources if r.get("Id")],
            message=f.get("Title", "Security Hub finding"),
            case_id=ctx.case_id,
            ventra_source="securityhub",
            raw=f,
        )


_INSPECTOR_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
    "UNTRIAGED": "info",
}


@register("inspector2")
def normalize_inspector2(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """Inspector2 vulnerability / network-reachability findings."""
    for f in records:
        resources = f.get("resources", []) or []
        res = resources[0] if resources else {}
        res_id = res.get("id", "")
        vuln = (f.get("packageVulnerabilityDetails", {}) or {}).get("vulnerabilityId", "")
        yield UnifiedEvent(
            timestamp=str(f.get("updatedAt", f.get("firstObservedAt", ""))),
            event_kind="finding",
            event_category=["threat"],
            event_action=vuln or f.get("type", ""),
            event_outcome="unknown",
            event_severity=_INSPECTOR_SEVERITY.get(str(f.get("severity", "")).upper(), "info"),
            event_provider="inspector2",
            cloud_account=f.get("awsAccountId", ctx.account_id),
            cloud_region=res.get("region", f.get("_ventra_region", "")),
            cloud_service="inspector2",
            resource_type=res.get("type", ""),
            resource_id=res_id.split("/")[-1] if res_id else "",
            resource_arn=res_id if res_id.startswith("arn:") else "",
            related_resource=[r.get("id", "") for r in resources if r.get("id")],
            message=f.get("title", vuln or "Inspector2 finding"),
            case_id=ctx.case_id,
            ventra_source="inspector2",
            raw=f,
        )


@register("macie")
def normalize_macie(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for f in records:
        resources = f.get("resourcesAffected", {}) or {}
        s3 = resources.get("s3Bucket", {}) or {}
        res_name = s3.get("name", "") or s3.get("arn", "")
        yield UnifiedEvent(
            timestamp=f.get("updatedAt", f.get("createdAt", "")),
            event_kind="finding",
            event_category=["threat"],
            event_action=f.get("type", f.get("category", "")),
            event_outcome="unknown",
            event_severity=_macie_severity(f),
            event_provider="macie",
            cloud_account=ctx.account_id,
            cloud_region=f.get("region", f.get("_ventra_region", "")),
            cloud_service="macie",
            resource_id=res_name,
            resource_arn=s3.get("arn", ""),
            related_resource=[res_name] if res_name else [],
            message=f.get("title", f.get("type", "Macie finding")),
            case_id=ctx.case_id,
            ventra_source="macie",
            raw=f,
        )


@register("detective")
def normalize_detective(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for inv in records:
        entity = inv.get("EntityArn", "")
        entity_type = inv.get("EntityType", "entity")
        sev = str(inv.get("Severity", "")).upper()
        yield UnifiedEvent(
            timestamp=inv.get("CreatedTime", ""),
            event_kind="finding",
            event_category=["threat"],
            event_action=inv.get("InvestigationId", entity_type),
            event_outcome="unknown",
            event_severity=_DETECTIVE_SEVERITY.get(sev, "info"),
            event_provider="detective",
            cloud_account=ctx.account_id,
            cloud_region=inv.get("_ventra_region", ""),
            cloud_service="detective",
            resource_arn=entity,
            resource_id=entity.split("/")[-1] if entity else "",
            related_resource=[entity] if entity else [],
            message=f"Detective investigation on {entity_type}"
            + (f" ({entity.split('/')[-1]})" if entity else ""),
            case_id=ctx.case_id,
            ventra_source="detective",
            raw=inv,
        )


@register("config")
def normalize_config(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """AWS Config compliance results as state events (NON_COMPLIANT bubbles up)."""
    for c in records:
        rule = c.get("ConfigRuleName", "")
        compliance = (c.get("Compliance", {}) or {}).get("ComplianceType", "")
        severity = "medium" if compliance == "NON_COMPLIANT" else "info"
        yield UnifiedEvent(
            timestamp=c.get("_ventra_ingest_ts", ""),
            event_kind="state",
            event_category=["configuration"],
            event_action=rule,
            event_outcome="failure" if compliance == "NON_COMPLIANT" else "success",
            event_severity=severity,
            event_provider="config",
            cloud_account=ctx.account_id,
            cloud_region=c.get("_ventra_region", ""),
            cloud_service="config",
            message=f"Config rule {rule}: {compliance}",
            case_id=ctx.case_id,
            ventra_source="config",
            raw=c,
        )


_DEFENDER_SEVERITY = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


@register("defender")
def normalize_defender(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for alert in records:
        props = alert.get("properties") or alert.get("Properties") or alert
        if not isinstance(props, dict):
            props = alert
        severity = _DEFENDER_SEVERITY.get(str(props.get("severity", "")).title(), "medium")
        name = props.get("alertDisplayName") or props.get("compromisedEntity") or "Defender alert"
        resource = props.get("compromisedEntity") or props.get("resourceIdentifiers", [{}])[0]
        if isinstance(resource, dict):
            resource_id = resource.get("azureResourceId") or resource.get("id") or ""
        else:
            resource_id = str(resource or "")
        yield UnifiedEvent(
            timestamp=props.get("startTimeUtc") or props.get("timeGeneratedUtc") or "",
            event_kind="finding",
            event_category=["threat"],
            event_action=props.get("alertType") or props.get("systemAlertId") or "defender_alert",
            event_outcome="unknown",
            event_severity=severity,
            event_provider="defender",
            cloud_provider="azure",
            cloud_account=ctx.account_id,
            cloud_region=props.get("resourceLocation") or "",
            cloud_service="defender",
            resource_id=resource_id,
            resource_arn=resource_id,
            related_resource=[resource_id] if resource_id else [],
            message=name,
            case_id=ctx.case_id,
            ventra_source="defender",
            raw=alert,
        )
