"""k8s_apiserver_audit — the API-server audit log (the crown jewel).

On-prem the audit log is a file on disk, not a cloud stream. It is the only record of *who
did what* inside the cluster — pods/exec, secret reads, RBAC changes. This collector reads
``--audit-log-path`` (and its rotated siblings), parses the ``audit.k8s.io/v1`` events, and
builds the priority detections an IR needs. If the file does not exist it emits a critical
LOGGING_NOT_CONFIGURED gap cross-linked to ``k8s_audit_posture``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.nodebase import NodePlaneCollector

_APISERVER_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
_DEFAULT_AUDIT_PATH = "/var/log/kubernetes/audit/audit.log"
_AUDIT_PATH_RE = re.compile(r"--audit-log-path[= ]([^\s\"']+)")

# Admin source-IP ranges are engagement-specific; the artifact param ``admin_cidrs`` narrows
# the "request from an unexpected source IP" detection. Empty = detection disabled.


class ApiserverAuditCollector(NodePlaneCollector):
    name = "k8s_apiserver_audit"
    priority = 1
    description = "API-server audit log from disk with who-did-what detections (on-prem exclusive)."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        gaps: list[tuple[str, GapReason, str]] = []
        nc = self.node_context()

        audit_path = self._resolve_audit_path(node)
        log_files = self._audit_files(node, audit_path)
        if not log_files:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        self.name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        f"No audit log found at {audit_path} (or rotated siblings). API-server "
                        "audit logging appears disabled — see k8s_audit_posture. This is the "
                        "single most important gap: there is no record of in-cluster activity.",
                    )
                ],
                notes="No audit log on disk.",
            )

        records: list[dict[str, Any]] = []
        raw_files = []
        parse_errors = 0
        for host_path in log_files:
            # Preserve the raw log verbatim (hashed on acquisition) alongside parsed records.
            wf = self.copy_node_file(host_path, self._dest_from_host_path(host_path))
            if wf is not None:
                raw_files.append(wf)
            for line in _iter_lines(node, host_path):
                rec = _parse_event(line)
                if rec is None:
                    parse_errors += 1
                    continue
                nc.stamp(rec)
                rec["_ventra_audit_file"] = host_path
                records.append(rec)

        detections = self._detections(records)
        files = list(raw_files)
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        files.append(self.write_json(detections, "detections.json"))
        files.append(
            self.write_json(
                {
                    "audit_path": audit_path,
                    "files": log_files,
                    "records": len(records),
                    "parse_errors": parse_errors,
                    "node": nc.to_dict(),
                    "detection_counts": {k: len(v) for k, v in detections.items()},
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "records": len(records)})

        for label, hits in detections.items():
            if hits:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"{len(hits)} audit event(s) matched detection '{label}'.",
                    )
                )

        status = SourceStatus.PARTIAL if (gaps and not records) else (
            SourceStatus.COLLECTED if records else SourceStatus.EMPTY
        )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} audit event(s) from {len(log_files)} file(s); "
            f"{sum(len(v) for v in detections.values())} detection hit(s).",
        )

    def _resolve_audit_path(self, node: Any) -> str:
        if node.exists(_APISERVER_MANIFEST):
            try:
                m = _AUDIT_PATH_RE.search(node.read_text(_APISERVER_MANIFEST))
                if m:
                    return m.group(1)
            except Exception:  # noqa: BLE001
                pass
        return _DEFAULT_AUDIT_PATH

    def _audit_files(self, node: Any, audit_path: str) -> list[str]:
        """The active audit log plus rotated siblings (``audit.log`` + ``audit-*.log``)."""
        out: list[str] = []
        if node.exists(audit_path):
            out.append(audit_path)
        base = audit_path.rsplit(".", 1)[0] if "." in audit_path.rsplit("/", 1)[-1] else audit_path
        for rotated in node.iter_glob(f"{base}-*"):
            host = "/" + rotated.relative_to(node.root).as_posix()
            if host not in out:
                out.append(host)
        return out

    def _detections(self, records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        from collector.lib.params import param_strings

        admin_cidrs = param_strings(self.artifact_params(), "admin_cidrs")
        det: dict[str, list[dict[str, Any]]] = {
            "exec_or_attach": [],
            "secret_read": [],
            "rbac_change": [],
            "privileged_pod_create": [],
            "delete_burst": [],
            "anonymous_subject": [],
            "unexpected_source_ip": [],
            "portforward": [],
        }
        deletes: list[dict[str, Any]] = []
        for rec in records:
            verb = str(rec.get("verb", "")).lower()
            obj = rec.get("objectRef") or {}
            resource = str(obj.get("resource", "")).lower()
            sub = str(obj.get("subresource", "")).lower()
            user = (rec.get("user") or {}).get("username", "")
            groups = (rec.get("user") or {}).get("groups") or []
            ips = rec.get("sourceIPs") or []

            if sub in ("exec", "attach"):
                det["exec_or_attach"].append(_slim(rec))
            if sub == "portforward":
                det["portforward"].append(_slim(rec))
            if verb in ("get", "list", "watch") and resource == "secrets":
                det["secret_read"].append(_slim(rec))
            if resource in ("clusterrolebindings", "rolebindings") and verb in (
                "create",
                "update",
                "patch",
            ):
                det["rbac_change"].append(_slim(rec))
            if resource == "pods" and verb == "create" and _is_privileged_request(rec):
                det["privileged_pod_create"].append(_slim(rec))
            if user in ("system:anonymous",) or "system:unauthenticated" in groups:
                det["anonymous_subject"].append(_slim(rec))
            if verb == "delete":
                deletes.append(rec)
            if admin_cidrs and ips and not _ip_in_admin_range(ips, admin_cidrs):
                det["unexpected_source_ip"].append(_slim(rec))

        det["delete_burst"] = _delete_bursts(deletes)
        return det


def _iter_lines(node: Any, host_path: str):
    try:
        text = node.read_text(host_path)
    except Exception:  # noqa: BLE001
        return
    for line in text.splitlines():
        if line.strip():
            yield line


def _parse_event(line: str) -> dict[str, Any] | None:
    try:
        rec = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(rec, dict):
        return None
    if rec.get("kind") == "EventList":
        return None
    return rec


def _slim(rec: dict[str, Any]) -> dict[str, Any]:
    obj = rec.get("objectRef") or {}
    return {
        "auditID": rec.get("auditID", ""),
        "stage": rec.get("stage", ""),
        "verb": rec.get("verb", ""),
        "user": (rec.get("user") or {}).get("username", ""),
        "impersonatedUser": (rec.get("impersonatedUser") or {}).get("username", ""),
        "sourceIPs": rec.get("sourceIPs", []),
        "resource": obj.get("resource", ""),
        "subresource": obj.get("subresource", ""),
        "namespace": obj.get("namespace", ""),
        "name": obj.get("name", ""),
        "responseCode": (rec.get("responseStatus") or {}).get("code"),
        "requestReceivedTimestamp": rec.get("requestReceivedTimestamp", ""),
    }


def _is_privileged_request(rec: dict[str, Any]) -> bool:
    obj = rec.get("requestObject") or {}
    spec = obj.get("spec") or {}
    if spec.get("hostPID") or spec.get("hostNetwork") or spec.get("hostIPC"):
        return True
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            return True
    return any(vol.get("hostPath") for vol in spec.get("volumes") or [])


def _delete_bursts(deletes: list[dict[str, Any]], *, threshold: int = 10) -> list[dict[str, Any]]:
    """Flag users who issued a burst of deletes — classic anti-forensics."""
    by_user: dict[str, int] = {}
    for rec in deletes:
        user = (rec.get("user") or {}).get("username", "")
        by_user[user] = by_user.get(user, 0) + 1
    return [
        {"user": user, "delete_count": count}
        for user, count in by_user.items()
        if count >= threshold
    ]


def _ip_in_admin_range(ips: list[str], cidrs: list[str]) -> bool:
    import ipaddress

    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in net for net in nets):
            return True
    return False
