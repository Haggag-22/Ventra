"""Kubernetes cluster-state and RBAC normalizers (on-prem).

``k8s_cluster_state`` and ``k8s_rbac`` each write one JSON-lines payload per object kind
(``pods.jsonl.gz``, ``clusterrolebindings.jsonl.gz``, …). The normalizer receives those
records mixed together, so it dispatches on ``_ventra_kind`` — the marker the collector
stamps onto every object, because the API server returns list items with ``kind`` unset.

These are ``state`` events, not activity: each one says "this object existed, and here is why
it matters". Severity comes from the verdict the collector already stamped onto the record
(``_ventra_suspicious`` for pods, ``_ventra_grants`` / ``_ventra_anonymous_subjects`` for
RBAC), so the rules live in one place and the timeline agrees with the collector's findings.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# Kinds that become timeline state events, and the action name each gets. Deliberately
# curated: replicasets, configmaps, services, ingresses and PVCs are collected and appear in
# the Resource Inventory panel and raw evidence, but as timeline rows they are pure volume.
_STATE_KINDS: dict[str, str] = {
    "pods": "PodSnapshot",
    "nodes": "NodeSnapshot",
    "namespaces": "NamespaceSnapshot",
    "serviceaccounts": "ServiceAccountSnapshot",
    "secrets": "SecretSnapshot",
    "deployments": "DeploymentSnapshot",
    "daemonsets": "DaemonSetSnapshot",
    "statefulsets": "StatefulSetSnapshot",
    "jobs": "JobSnapshot",
    "cronjobs": "CronJobSnapshot",
    "persistentvolumes": "PersistentVolumeSnapshot",
    "networkpolicies": "NetworkPolicySnapshot",
    "customresourcedefinitions": "CustomResourceDefinitionSnapshot",
    "mutatingwebhookconfigurations": "MutatingWebhookSnapshot",
    "validatingwebhookconfigurations": "ValidatingWebhookSnapshot",
    "roles": "RoleSnapshot",
    "clusterroles": "ClusterRoleSnapshot",
    "rolebindings": "RoleBindingSnapshot",
    "clusterrolebindings": "ClusterRoleBindingSnapshot",
}

# Singular resource_type per kind, for the Resources / Search facets.
_RESOURCE_TYPES = {k: k.rstrip("s") if k.endswith("s") else k for k in _STATE_KINDS}
_RESOURCE_TYPES.update(
    {
        "persistentvolumes": "persistentvolume",
        "customresourcedefinitions": "crd",
        "mutatingwebhookconfigurations": "mutatingwebhook",
        "validatingwebhookconfigurations": "validatingwebhook",
        "networkpolicies": "networkpolicy",
    }
)

# A hostPath match on one of these is node takeover, not just node access.
_CRITICAL_HOSTPATHS = (
    "hostPath!:",  # the collector's own marker for a dangerous path
)


def _meta(rec: dict[str, Any]) -> dict[str, Any]:
    meta = rec.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _created(rec: dict[str, Any]) -> str:
    meta = _meta(rec)
    return str(meta.get("creation_timestamp") or meta.get("creationTimestamp") or "")


def _qualified_name(rec: dict[str, Any]) -> str:
    meta = _meta(rec)
    ns = str(meta.get("namespace") or "")
    name = str(meta.get("name") or "")
    return f"{ns}/{name}" if ns else name


def _pod_severity(findings: list[str]) -> str:
    """A flagged pod is medium; node-takeover shapes are high."""
    joined = " ".join(findings)
    if any(marker in joined for marker in _CRITICAL_HOSTPATHS):
        return "high"
    if any(f.startswith("privileged:") for f in findings) or "hostPID" in findings:
        return "high"
    return "medium"


def _pod_images(rec: dict[str, Any]) -> list[str]:
    spec = rec.get("spec") or {}
    out: list[str] = []
    for key in ("containers", "init_containers", "initContainers"):
        for container in spec.get(key) or []:
            if isinstance(container, dict) and container.get("image"):
                out.append(str(container["image"]))
    return out


def _describe(kind: str, rec: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Return ``(severity, message, related)`` for one object."""
    name = _qualified_name(rec)
    related: list[str] = [name] if name else []

    if kind == "pods":
        findings = [str(f) for f in (rec.get("_ventra_suspicious") or [])]
        images = _pod_images(rec)
        related.extend(images)
        if findings:
            return (
                _pod_severity(findings),
                f"Pod {name} flagged: {', '.join(findings)}",
                related,
            )
        return "info", f"Pod {name}" + (f" running {', '.join(images)}" if images else ""), related

    if kind in ("clusterrolebindings", "rolebindings"):
        ref = rec.get("role_ref") or rec.get("roleRef") or {}
        role = f"{ref.get('kind', '')}/{ref.get('name', '')}".strip("/")
        subjects = [
            str(s.get("name", ""))
            for s in (rec.get("subjects") or [])
            if isinstance(s, dict) and s.get("name")
        ]
        related.extend(subjects)
        anonymous = [str(a) for a in (rec.get("_ventra_anonymous_subjects") or [])]
        grants = [str(g) for g in (rec.get("_ventra_grants") or [])]
        if anonymous:
            return (
                "critical",
                f"{role} is bound to {', '.join(anonymous)} — unauthenticated callers hold "
                f"these permissions" + (f" ({', '.join(grants)})" if grants else ""),
                related,
            )
        if grants:
            return (
                "high",
                f"{name} grants {role} to {', '.join(subjects) or 'no subject'}: {', '.join(grants)}",
                related,
            )
        return "info", f"{name} grants {role} to {', '.join(subjects) or 'no subject'}", related

    if kind in ("roles", "clusterroles"):
        grants = [str(g) for g in (rec.get("_ventra_grants") or [])]
        if grants:
            return "medium", f"{name} grants: {', '.join(grants)}", related
        return "info", f"{kind[:-1]} {name}", related

    if kind == "mutatingwebhookconfigurations":
        # A rogue mutating webhook silently injects containers cluster-wide.
        targets = _webhook_targets(rec)
        related.extend(targets)
        return (
            "high",
            f"MutatingWebhookConfiguration {name} can rewrite every admitted object"
            + (f" (endpoint: {', '.join(targets)})" if targets else ""),
            related,
        )

    if kind == "validatingwebhookconfigurations":
        targets = _webhook_targets(rec)
        related.extend(targets)
        return (
            "medium",
            f"ValidatingWebhookConfiguration {name}"
            + (f" (endpoint: {', '.join(targets)})" if targets else ""),
            related,
        )

    if kind == "namespaces":
        labels = _meta(rec).get("labels") or {}
        enforce = str(labels.get("pod-security.kubernetes.io/enforce", ""))
        if enforce == "privileged":
            return (
                "medium",
                f"Namespace {name} enforces the 'privileged' Pod Security level — "
                "privileged and hostPath pods are admitted without restriction",
                related,
            )
        return "info", f"Namespace {name}" + (f" (PSA enforce={enforce})" if enforce else ""), related

    if kind == "persistentvolumes":
        spec = rec.get("spec") or {}
        host_path = spec.get("host_path") or spec.get("hostPath") or {}
        if host_path:
            return (
                "medium",
                f"PersistentVolume {name} is hostPath-backed at {host_path.get('path', '')} — "
                "any pod that binds it reads and writes the node filesystem",
                related,
            )
        return "info", f"PersistentVolume {name}", related

    if kind == "serviceaccounts":
        raw = rec.get("automount_service_account_token")
        if raw is None:
            raw = rec.get("automountServiceAccountToken")
        automount = True if raw is None else bool(raw)
        return (
            "info",
            f"ServiceAccount {name}"
            + (" (token automounted into every pod)" if automount else " (automount disabled)"),
            related,
        )

    if kind == "cronjobs":
        schedule = str((rec.get("spec") or {}).get("schedule", ""))
        return (
            "info",
            f"CronJob {name}" + (f" on schedule '{schedule}'" if schedule else ""),
            related,
        )

    if kind == "nodes":
        info = (
            ((rec.get("status") or {}).get("node_info")) or ((rec.get("status") or {}).get("nodeInfo")) or {}
        )
        detail = " ".join(
            str(info.get(k, ""))
            for k in ("kubelet_version", "kubeletVersion", "os_image", "osImage")
            if info.get(k)
        )
        return "info", f"Node {name} {detail}".strip(), related

    if kind == "secrets":
        return "info", f"Secret {name} (type {rec.get('type', 'unknown')}, metadata only)", related

    return "info", f"{_RESOURCE_TYPES.get(kind, kind)} {name}", related


def _webhook_targets(rec: dict[str, Any]) -> list[str]:
    """Where each webhook's ``clientConfig`` points — a URL outside the cluster is notable."""
    out: list[str] = []
    for hook in rec.get("webhooks") or []:
        if not isinstance(hook, dict):
            continue
        cc = hook.get("client_config") or hook.get("clientConfig") or {}
        if cc.get("url"):
            out.append(str(cc["url"]))
        svc = cc.get("service") or {}
        if svc:
            out.append(f"{svc.get('namespace', '')}/{svc.get('name', '')}")
    return out


def _state_events(records: list[dict], ctx: NormalizeContext, provider: str) -> Iterator[UnifiedEvent]:
    for rec in records:
        kind = str(rec.get("_ventra_kind", ""))
        action = _STATE_KINDS.get(kind)
        if action is None:
            continue
        severity, message, related = _describe(kind, rec)
        cluster = str(rec.get("_ventra_cluster") or ctx.account_id)
        name = _qualified_name(rec)
        yield UnifiedEvent(
            timestamp=_created(rec),
            event_kind="state",
            event_category=["kubernetes", "configuration"],
            event_action=action,
            event_outcome="success",
            event_severity=severity,
            event_provider=provider,
            cloud_provider="kubernetes",
            cloud_account=cluster,
            cloud_service="kubernetes",
            resource_type=_RESOURCE_TYPES.get(kind, kind),
            resource_id=name or cluster,
            related_resource=[r for r in ([cluster] + related) if r],
            message=message,
            case_id=ctx.case_id,
            ventra_source=provider,
            raw=rec,
        )


@register("k8s_cluster_state")
def normalize_k8s_cluster_state(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    return _state_events(records, ctx, "k8s_cluster_state")


@register("k8s_rbac")
def normalize_k8s_rbac(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    return _state_events(records, ctx, "k8s_rbac")
