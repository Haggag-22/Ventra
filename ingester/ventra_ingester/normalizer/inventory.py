"""Inventory extraction for snapshot sources.

Sources like iam, ec2, s3, kms, secrets, account, waf, and lambda are point-in-time
snapshots rather than event streams. They are stored as JSON under ``cases/<id>/inventory/``
and rendered by the console's Resources and Identity panels. A handful also emit derived
*state* events (e.g. each IAM principal) so they appear on the Timeline when relevant.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterator

from .base import NormalizeContext, UnifiedEvent

INVENTORY_SOURCES = {
    "iam", "ec2", "s3", "kms", "secrets", "account", "waf", "lambda",
    "rbac", "subscription", "entra_directory", "resource_graph",
    "project", "iam_policy",
}


def parse_credential_report(csv_bytes: bytes) -> list[dict[str, Any]]:
    text = csv_bytes.decode("utf-8", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def iam_state_events(snapshot: dict, ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """Emit one 'state' event per IAM user with key-hygiene severity, for the Timeline/Identity
    cross-link. Old or unused access keys raise severity."""
    for user in snapshot.get("users", []):
        keys = user.get("AccessKeys", []) or []
        severity = "info"
        oldest_note = ""
        for k in keys:
            last = (k.get("LastUsed", {}) or {}).get("LastUsedDate")
            if k.get("Status") == "Active" and not last:
                severity = "medium"
                oldest_note = "active key never used"
        yield UnifiedEvent(
            timestamp=user.get("CreateDate", ""),
            event_kind="state",
            event_category=["iam"],
            event_action="IAMUserSnapshot",
            event_severity=severity,
            event_provider="iam",
            cloud_account=ctx.account_id,
            cloud_service="iam",
            user_name=user.get("UserName", ""),
            user_arn=user.get("Arn", ""),
            user_type="IAMUser",
            resource_type="iam-user",
            resource_id=user.get("UserName", ""),
            resource_arn=user.get("Arn", ""),
            related_user=[user.get("UserName", ""), user.get("Arn", "")],
            message=f"IAM user {user.get('UserName','')}"
            + (f" — {oldest_note}" if oldest_note else ""),
            case_id=ctx.case_id,
            ventra_source="iam",
            raw={"UserName": user.get("UserName"), "AccessKeys": keys},
        )


def iam_policy_state_events(snapshot: dict, ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """Emit one state event per GCP service account with user-managed keys for Timeline/Identity."""
    for project in snapshot.get("projects") or []:
        project_id = str(project.get("project_id") or ctx.account_id)
        for sa in project.get("service_accounts") or []:
            keys = sa.get("keys") or []
            severity = "info"
            note = ""
            for key in keys:
                if key.get("keyType") == "USER_MANAGED" and not key.get("disabled"):
                    severity = "medium"
                    note = "user-managed service account key"
                    break
            email = str(sa.get("email") or "")
            name = str(sa.get("name") or email)
            yield UnifiedEvent(
                timestamp="",
                event_kind="state",
                event_category=["iam"],
                event_action="GCPServiceAccountSnapshot",
                event_severity=severity,
                event_provider="gcp",
                cloud_provider="gcp",
                cloud_account=project_id,
                cloud_service="iam",
                user_name=email,
                user_arn=name,
                user_type="ServiceAccount",
                resource_type="gcp-service-account",
                resource_id=email,
                resource_arn=name,
                related_user=[email, name],
                message=f"GCP service account {email}"
                + (f" — {note}" if note else ""),
                case_id=ctx.case_id,
                ventra_source="iam_policy",
                raw={"email": email, "keys": keys},
            )
