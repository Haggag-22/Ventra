"""Shared Unified Audit Log constants, runbooks, and record shaping."""

from __future__ import annotations

import json
from typing import Any

# Management Activity API content feeds (near-real-time; ~7-day API horizon).
MANAGEMENT_CONTENT_TYPES: tuple[str, ...] = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.General",
    "Audit.SharePoint",
    "Audit.Teams",
    "DLP.All",
)

# Search-UnifiedAuditLog RecordType groups (Invictus-style) for optional targeted pulls.
SEARCH_RECORD_TYPE_GROUPS: dict[str, tuple[str, ...]] = {
    "Exchange": (
        "ExchangeAdmin",
        "ExchangeAggregatedOperation",
        "ExchangeItem",
        "ExchangeItemGroup",
        "ExchangeItemAggregated",
        "ComplianceDLPExchange",
        "ComplianceSupervisionExchange",
    ),
    "Azure": (
        "AzureActiveDirectory",
        "AzureActiveDirectoryAccountLogon",
        "AzureActiveDirectoryStsLogon",
    ),
    "SharePoint": (
        "ComplianceDLPSharePoint",
        "SharePoint",
        "SharePointFileOperation",
        "SharePointSharingOperation",
        "SharepointListOperation",
        "ComplianceDLPSharePointClassification",
        "SharePointCommentOperation",
        "SharePointListItemOperation",
        "SharePointContentTypeOperation",
        "SharePointFieldOperation",
        "MipAutoLabelSharePointItem",
        "MipAutoLabelSharePointPolicyLocation",
    ),
    "Skype": (
        "SkypeForBusinessCmdlets",
        "SkypeForBusinessPSTNUsage",
        "SkypeForBusinessUsersBlocked",
    ),
    "Defender": (
        "ThreatIntelligence",
        "ThreatFinder",
        "ThreatIntelligenceUrl",
        "ThreatIntelligenceAtpContent",
        "Campaign",
        "AirInvestigation",
        "WDATPAlerts",
        "AirManualInvestigation",
        "AirAdminActionInvestigation",
        "MSTIC",
        "MCASAlerts",
    ),
}

FEED_ENABLE_RUNBOOK = (
    "Enable Microsoft Purview audit logging for the tenant, then start the Office 365 "
    "Management Activity API subscription for each content type (Microsoft Purview compliance "
    "portal → Audit → turn on Unified Audit Log; connect SIEM/API feed for the content type). "
    "Ventra is read-only and will not start feeds."
)

SEARCH_PERMISSION_RUNBOOK = (
    "Grant the app registration Exchange.ManageAsApp (Office 365 Exchange Online application "
    "permission) and assign the service principal an Exchange Administrator (or Audit Logs) "
    "role in Entra ID. Search-UnifiedAuditLog uses the Exchange Online Admin API."
)

RETENTION_NOTE = (
    "Microsoft 365 audit retention is typically 180 days (Audit Standard) or 365 days "
    "(Audit Premium). Ventra records the requested window in _meta.json; tenant license "
    "tier is not queried automatically."
)

API_CAP_PER_SEARCH_CALL = 5000


def feed_gap_detail(content_type: str, exc_message: str) -> str:
    return f"{content_type}: {exc_message}. {FEED_ENABLE_RUNBOOK}"


def flatten_search_row(row: dict[str, Any], *, audit_data_only: bool) -> dict[str, Any]:
    """Turn a Search-UnifiedAuditLog row into a UAL-shaped dict for the normalizer."""
    audit_raw = row.get("AuditData") or "{}"
    if isinstance(audit_raw, str):
        try:
            audit: dict[str, Any] = json.loads(audit_raw)
        except json.JSONDecodeError:
            audit = {}
    elif isinstance(audit_raw, dict):
        audit = dict(audit_raw)
    else:
        audit = {}

    if audit_data_only:
        out = dict(audit)
    else:
        out = dict(audit)
        wrapper = {k: v for k, v in row.items() if k != "AuditData"}
        if wrapper:
            out["_ventra_search_wrapper"] = wrapper

    out["_ventra_ual_acquisition"] = "search_unified_audit_log"
    if not out.get("CreationTime") and row.get("CreationDate"):
        out["CreationTime"] = row.get("CreationDate")
    if not out.get("UserId") and row.get("UserIds"):
        out["UserId"] = row.get("UserIds")
    if not out.get("Operation") and row.get("Operations"):
        out["Operation"] = row.get("Operations")
    return out


def tag_management_record(rec: dict[str, Any]) -> dict[str, Any]:
    tagged = dict(rec)
    tagged["_ventra_ual_acquisition"] = "management_activity_api"
    return tagged
