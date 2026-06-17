"""Microsoft 365 normalizers — Unified Audit Log + OAuth consent grants.

The UAL is one stream carrying many workloads; this routes each record to the right lens by
``Operation`` / ``Workload``: ``MailItemsAccessed`` and mailbox ops → Data Access (BEC exfil
scoping), Entra ops → Identity, consent / credential-add / inbox-rule ops → persistence, and
everything else → control-plane (the Azure 'Activity Log Timeline' panel). OAuth permission
grants are emitted as findings (illicit-app persistence).
"""

from __future__ import annotations

from typing import Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# Operations that signal attacker persistence / hiding (auto-forward rules, illicit consent,
# service-principal credential adds). Matched case-insensitively by prefix.
_PERSISTENCE_OPS = (
    "new-inboxrule",
    "set-inboxrule",
    "updateinboxrules",
    "new-transportrule",
    "set-transportrule",
    "consent to application",
    "add delegated permission grant",
    "add app role assignment grant",
    "add service principal credentials",
    "add owner to application",
)
_MAILBOX_OPS = {"mailitemsaccessed", "messagebind", "send", "sendas", "sendonbehalf", "hardelete",
                "softdelete", "movetodeleteditems", "create", "update"}


def _ual_outcome(status: str) -> str:
    s = (status or "").lower()
    if s in ("succeeded", "success", "true", "partiallysucceeded", ""):
        return "success"
    return "failure"


def _classify(op: str, workload: str) -> tuple[list[str], str]:
    low = op.lower()
    if low == "mailitemsaccessed":
        return ["data", "mailbox"], "info"
    if any(low.startswith(p) for p in _PERSISTENCE_OPS):
        return ["identity", "persistence"], "high"
    if workload == "AzureActiveDirectory":
        return ["identity"], "info"
    if workload in ("Exchange", "OneDrive", "SharePoint") and low in _MAILBOX_OPS:
        return ["data"], "info"
    return ["control_plane"], "info"


@register("unified_audit")
def normalize_unified_audit(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        op = rec.get("Operation", "")
        workload = rec.get("Workload", "")
        user = rec.get("UserId", "")
        ip = rec.get("ClientIP") or rec.get("ClientIPAddress") or rec.get("ActorIpAddress") or ""
        obj = rec.get("ObjectId") or ""
        categories, severity = _classify(op, workload)
        outcome = _ual_outcome(rec.get("ResultStatus", ""))
        if outcome == "failure" and severity == "info":
            severity = "low"
        yield UnifiedEvent(
            timestamp=rec.get("CreationTime") or "",
            event_kind="event",
            event_category=categories,
            event_action=op,
            event_outcome=outcome,
            event_severity=severity,
            event_provider="m365",
            cloud_provider="azure",
            cloud_account=rec.get("OrganizationId") or ctx.account_id,
            cloud_service=workload or "m365",
            user_name=user,
            user_id=rec.get("UserKey") or "",
            source_ip=ip,
            resource_id=obj,
            resource_arn=obj,
            related_ip=[ip] if ip else [],
            related_user=[user] if user else [],
            related_resource=[obj] if obj else [],
            message=f"{op} by {user}" + (f" on {obj}" if obj else ""),
            case_id=ctx.case_id,
            ventra_source="unified_audit",
            raw=rec,
        )


@register("oauth_consent")
def normalize_oauth_consent(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        client = rec.get("clientId") or ""
        principal = rec.get("principalId") or ""
        consent_type = rec.get("consentType") or ""
        scope = (rec.get("scope") or "").strip()
        who = principal or ("all users" if consent_type.lower() == "allprincipals" else "")
        yield UnifiedEvent(
            timestamp="",
            event_kind="finding",
            event_category=["identity", "persistence"],
            event_action="oauth2-permission-grant",
            event_outcome="unknown",
            event_severity="medium",
            event_provider="oauth_consent",
            cloud_provider="azure",
            cloud_account=ctx.account_id,
            cloud_service="entra",
            user_id=principal,
            resource_id=client,
            resource_arn=client,
            related_user=[principal] if principal else [],
            related_resource=[r for r in (client, rec.get("resourceId") or "") if r],
            message=(
                f"OAuth grant to app {client}"
                + (f" for {who}" if who else "")
                + (f": {scope}" if scope else "")
            ),
            case_id=ctx.case_id,
            ventra_source="oauth_consent",
            raw=rec,
        )
