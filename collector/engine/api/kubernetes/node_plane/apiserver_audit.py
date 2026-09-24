"""k8s_apiserver_audit — the API-server audit log (the crown jewel).

On-prem the audit log is a file on disk, not a cloud stream. It is the only record of *who
did what* inside the cluster: pods/exec, secret reads, RBAC changes. This collector reads the
active file plus its rotated siblings (including ``.gz``), parses the ``audit.k8s.io/v1``
events, and builds the priority detections an IR needs.

``--audit-log-path`` is resolved from whatever the distribution uses to declare it, so the
collector does not depend on a kubeadm static pod manifest existing:

* kubeadm and RKE2 static pod manifests;
* ``/etc/rancher/k3s/config.yaml`` and ``/etc/rancher/rke2/config.yaml``;
* the server unit's ``ExecStart`` line (k3s, RKE2);
* ``/var/snap/microk8s/current/args/kube-apiserver``.

If none of those resolve, the documented default paths are still searched, which is why a
default k3s install works: it writes ``/var/log/kubernetes/audit/audit.log`` with no manifest
anywhere on the node. Every path searched is recorded in ``config.json``.

Two distinct absences are reported differently, because they mean different things:
  * nothing configured at all -> critical ``LOGGING_NOT_CONFIGURED``;
  * a webhook-only backend (``--audit-webhook-config-file`` with no local file) -> the
    evidence exists but lives in an external sink, so ``NOT_PRESENT`` with the sink named.
Both cross-link ``k8s_audit_posture``.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.apiserver_flags import read_apiserver_flags
from ..common.nodebase import NodePlaneCollector

_APISERVER_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"

# Where the audit log lives when the flag cannot be read from the manifest. kubeadm writes the
# first; distro packages and several hardening guides use the others.
_DEFAULT_AUDIT_PATHS = (
    "/var/log/kubernetes/audit/audit.log",
    "/var/log/kube-apiserver-audit.log",
    "/var/log/kubernetes/kube-apiserver-audit.log",
    "/var/log/apiserver/audit.log",
)

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

        backend = self._resolve_backend(node)
        log_files = self._audit_files(node, backend["candidates"])
        if not log_files:
            return self._no_audit_log(backend, nc)

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
                self.distro().stamp(rec)
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
                    "audit_path": backend["configured_path"] or (log_files[0] if log_files else ""),
                    "audit_path_source": backend["source"],
                    "audit_webhook_config_file": backend["webhook_config"],
                    "distro": self.distro().to_dict(),
                    "flag_sources": backend["flag_sources"],
                    "flags_searched": backend["flags_searched"],
                    "files": log_files,
                    "records": len(records),
                    "parse_errors": parse_errors,
                    "node": nc.to_dict(),
                    "detection_counts": {k: len(v) for k, v in detections.items()},
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "records": len(records), "distro": self.distro().family})

        if backend["webhook_config"]:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "A webhook audit backend is also configured "
                    f"(--audit-webhook-config-file={backend['webhook_config']}); events may be "
                    "delivered to an external sink that this node-plane capture does not cover. "
                    "Collect from that sink as well — see k8s_audit_posture.",
                )
            )
        for label, hits in detections.items():
            if hits:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"{len(hits)} audit event(s) matched detection '{label}'.",
                    )
                )

        status = (
            SourceStatus.PARTIAL
            if (gaps and not records)
            else (SourceStatus.COLLECTED if records else SourceStatus.EMPTY)
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

    # -- backend / path resolution --------------------------------------------------------

    def _resolve_backend(self, node: Any) -> dict[str, Any]:
        """Resolve where the audit log should be, from this distro's flags then the defaults."""
        distro = self.distro()
        resolved = read_apiserver_flags(node, distro)
        out: dict[str, Any] = {
            "configured_path": "",
            "webhook_config": resolved.get("audit-webhook-config-file"),
            "flags_determined": resolved.determined,
            "flag_sources": resolved.evidence,
            "flags_searched": resolved.searched,
            "distro": distro.family,
            "source": "",
            "candidates": list(_DEFAULT_AUDIT_PATHS),
        }

        configured = resolved.get("audit-log-path")
        if configured:
            origin = resolved.origins.get("audit-log-path", "kube-apiserver flags")
            out["configured_path"] = configured
            out["source"] = f"{origin} (--audit-log-path={configured})"
            # The configured path wins, but still try the defaults: on a rotated-away or
            # relocated log a sibling default occasionally holds the evidence.
            out["candidates"] = [configured] + [p for p in _DEFAULT_AUDIT_PATHS if p != configured]
        elif resolved.determined:
            out["source"] = (
                f"no --audit-log-path in {', '.join(resolved.evidence)}; "
                "searching the documented default paths"
            )
        else:
            out["source"] = (
                f"no kube-apiserver flag source readable on this {distro.family} node; "
                "searching the documented default paths"
            )
        return out

    def _audit_files(self, node: Any, candidates: list[str]) -> list[str]:
        """Every existing audit log: each candidate plus its rotated siblings (incl. ``.gz``)."""
        out: list[str] = []
        for audit_path in candidates:
            if audit_path not in out and node.exists(audit_path) and not node.is_dir(audit_path):
                out.append(audit_path)
            # kube-apiserver rotates to ``audit-<timestamp>.log`` next to the active file.
            name = audit_path.rsplit("/", 1)[-1]
            base = audit_path.rsplit(".", 1)[0] if "." in name else audit_path
            for pattern in (f"{base}-*", f"{audit_path}.*"):
                for rotated in node.iter_glob(pattern):
                    if not rotated.is_file():
                        continue
                    host = "/" + rotated.relative_to(node.root).as_posix()
                    if host not in out:
                        out.append(host)
        return out

    def _no_audit_log(self, backend: dict[str, Any], nc: Any) -> SourceResult:
        """No audit file on this node: distinguish webhook-only from not-configured-at-all."""
        searched = ", ".join(backend["candidates"])
        distro = self.distro()
        where = (
            f"kube-apiserver flags read from {', '.join(backend['flag_sources'])}"
            if backend["flag_sources"]
            else f"no kube-apiserver flag source found on this {distro.family} node "
            f"(looked at: {', '.join(backend['flags_searched']) or 'nothing applicable'})"
        )
        if backend["webhook_config"]:
            reason = GapReason.NOT_PRESENT
            detail = (
                "The API server audits to a WEBHOOK backend only "
                f"(--audit-webhook-config-file={backend['webhook_config']}) — no audit file "
                f"exists on this node (searched: {searched}; {where}). The who-did-what "
                "record lives in the external sink that webhook points at; collect it from "
                "there. See k8s_audit_posture for the configured backend."
            )
            notes = "Audit backend is webhook-only; no local file."
        else:
            reason = GapReason.LOGGING_NOT_CONFIGURED
            detail = (
                f"No audit log found on this node (searched: {searched}; {where}) and no "
                "webhook backend is configured. API-server audit logging appears DISABLED: "
                "see k8s_audit_posture. This is the single most important gap, because there "
                "is no record of in-cluster activity (no pods/exec, no secret reads, no RBAC "
                f"changes). On a {distro.family} {distro.role} node this is conclusive only if "
                "this is where the API server runs."
            )
            notes = "No audit log on disk."
        self.write_json(
            {
                "audit_path": backend["configured_path"],
                "audit_path_source": backend["source"],
                "audit_webhook_config_file": backend["webhook_config"],
                "distro": self.distro().to_dict(),
                "flag_sources": backend["flag_sources"],
                "flags_searched": backend["flags_searched"],
                "searched": backend["candidates"],
                "files": [],
                "records": 0,
                "node": nc.to_dict(),
            },
            "config.json",
        )
        self.write_meta({"source": self.name, "records": 0, "distro": self.distro().family})
        return SourceResult(
            name=self.name,
            status=SourceStatus.EMPTY,
            gaps=[(self.name, reason, detail)],
            notes=notes,
        )

    # -- detections -----------------------------------------------------------------------

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


def _iter_lines(node: Any, host_path: str) -> Iterator[str]:
    """Yield non-blank lines from an audit log, transparently decompressing ``.gz``."""
    path = node.resolve(host_path)
    try:
        if host_path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip():
                        yield line
            return
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    yield line
    except OSError:
        return


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
    return [{"user": user, "delete_count": count} for user, count in by_user.items() if count >= threshold]


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
