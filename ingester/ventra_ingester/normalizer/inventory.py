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
    "iam",
    "ec2",
    "s3",
    "kms",
    "secrets",
    "account",
    "waf",
    "lambda",
    "rbac",
    "subscription",
    "entra_directory",
    "resource_graph",
    "project",
    "iam_policy",
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
            message=f"IAM user {user.get('UserName', '')}" + (f" — {oldest_note}" if oldest_note else ""),
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
                message=f"GCP service account {email}" + (f" — {note}" if note else ""),
                case_id=ctx.case_id,
                ventra_source="iam_policy",
                raw={"email": email, "keys": keys},
            )


# -- Kubernetes (on-prem) -------------------------------------------------------------------
# The Kubernetes collectors write several named JSON sidecars per source (config.json plus
# derived artefacts like suspicious_pods.json, pod_security.json, images.json). These sources
# are snapshots, so they populate the Resource Inventory panel; the event payloads are
# normalized separately by the k8s_state / k8s_logs normalizers.
K8S_INVENTORY_SOURCES = {
    "k8s_cluster_state",
    "k8s_rbac",
    "k8s_audit_posture",
    "k8s_apiserver_audit",
    "k8s_etcd",
    "k8s_runtime_logs",
    "k8s_container_logs",
}


def k8s_posture_events(source: str, snapshot: dict, ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    """Turn Kubernetes posture snapshots into first-class timeline findings.

    "There is no audit log" is the most consequential result a Kubernetes IR can produce, so
    it belongs on the timeline as a critical finding — not only in the manifest's gap list.
    The same applies to etcd running without client-certificate auth or encryption at rest.
    """
    cluster = str(snapshot.get("_cluster") or ctx.account_id)

    if source == "k8s_audit_posture":
        config = snapshot.get("_config") or {}
        if not isinstance(config, dict) or not config:
            return
        enabled = bool(config.get("audit_enabled"))
        weaknesses = [str(w) for w in (config.get("policy_weaknesses") or [])]
        if not enabled:
            message = (
                "API-server audit logging is DISABLED — there is no record of who did what in "
                "this cluster (no pods/exec, no secret reads, no RBAC changes)"
            )
            severity = "critical"
        elif weaknesses:
            message = "Audit logging is enabled but the policy is weak: " + "; ".join(weaknesses)
            severity = "high"
        else:
            message = "API-server audit logging is enabled with a policy covering sensitive resources"
            severity = "info"
        yield UnifiedEvent(
            timestamp=ctx.collected_at,
            event_kind="finding",
            event_category=["kubernetes", "configuration"],
            event_action="AuditLoggingPosture",
            event_outcome="failure" if not enabled else "success",
            event_severity=severity,
            event_provider="k8s_audit_posture",
            cloud_provider="kubernetes",
            cloud_account=cluster,
            cloud_service="kubernetes",
            resource_type="cluster",
            resource_id=cluster,
            related_resource=[cluster],
            message=message,
            case_id=ctx.case_id,
            ventra_source="k8s_audit_posture",
            raw=config,
        )
        return

    if source == "k8s_etcd":
        config = snapshot.get("_config") or {}
        posture = (config or {}).get("posture") or {}
        for issue in posture.get("issues") or []:
            yield UnifiedEvent(
                timestamp=ctx.collected_at,
                event_kind="finding",
                event_category=["kubernetes", "configuration"],
                event_action="EtcdPosture",
                event_outcome="failure",
                event_severity="high",
                event_provider="k8s_etcd",
                cloud_provider="kubernetes",
                cloud_account=cluster,
                cloud_service="etcd",
                resource_type="etcd",
                resource_id=cluster,
                related_resource=[cluster],
                message=str(issue),
                case_id=ctx.case_id,
                ventra_source="k8s_etcd",
                raw={"issue": str(issue), "flags": posture.get("flags") or {}},
            )
        return
