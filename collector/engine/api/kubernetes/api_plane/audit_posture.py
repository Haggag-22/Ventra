"""k8s_audit_posture — is API-server audit logging even on?

The most common finding in a Kubernetes IR is "there is no audit log." That must be a
first-class, prominently-surfaced result — not a silent absence. This collector reports
whether ``--audit-log-path`` and ``--audit-policy-file`` are set, what the policy actually
logs, and the rotation settings, reading the kube-apiserver static pod manifest via the node
plane when available and degrading to a clear gap when it is not.
"""

from __future__ import annotations

import re
from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.analysis import audit_policy_weaknesses

_APISERVER_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
_FLAGS = (
    "audit-log-path",
    "audit-policy-file",
    "audit-log-maxage",
    "audit-log-maxbackup",
    "audit-log-maxsize",
    "audit-webhook-config-file",
)


class AuditPostureCollector(Collector):
    name = "k8s_audit_posture"
    priority = 1
    plane = "api"
    description = "API-server audit-logging posture: is it on, and is the policy useful?"
    required_actions = ()

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        node = getattr(cf, "node", None)
        gaps: list[tuple[str, GapReason, str]] = []

        if node is None or not node.exists(_APISERVER_MANIFEST):
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "kube-apiserver static pod manifest not readable from the node plane; audit "
                    "posture could not be determined from disk. Run the node-plane collector on "
                    "a control-plane node to confirm.",
                )
            )
            self.write_json({"determined": False, "reason": "node plane unavailable"}, "config.json")
            self.write_meta({"source": self.name, "determined": False})
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps,
                notes="Audit posture undetermined (control-plane node not reachable).",
            )

        manifest_text = node.read_text(_APISERVER_MANIFEST)
        flags = _extract_flags(manifest_text)
        audit_enabled = bool(flags.get("audit-log-path"))
        policy_path = flags.get("audit-policy-file", "")

        policy: dict[str, Any] = {}
        weaknesses: list[str] = []
        if policy_path and node.exists(policy_path):
            try:
                import yaml  # noqa: PLC0415

                policy = yaml.safe_load(node.read_text(policy_path)) or {}
                weaknesses = audit_policy_weaknesses(policy)
            except Exception as exc:  # noqa: BLE001
                gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"policy parse: {exc}"))

        webhook = bool(flags.get("audit-webhook-config-file"))

        if not audit_enabled:
            gaps.append(
                (
                    self.name,
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "CRITICAL: API-server audit logging is DISABLED (no --audit-log-path). There "
                    "is no record of who did what in this cluster — no pods/exec, no secret reads, "
                    "no RBAC changes. This is the single most important gap in the report.",
                )
            )
        elif weaknesses:
            gaps.append(
                (
                    self.name,
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "Audit logging is enabled but the policy is weak: " + "; ".join(weaknesses),
                )
            )

        config = {
            "audit_enabled": audit_enabled,
            "flags": flags,
            "audit_policy_file": policy_path,
            "audit_policy": policy,
            "policy_weaknesses": weaknesses,
            "webhook_backend": webhook,
        }
        files = [self.write_json(config, "config.json")]
        self.write_meta(
            {"source": self.name, "audit_enabled": audit_enabled, "weaknesses": len(weaknesses)}
        )
        status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=1,
            gaps=gaps,
            notes=(
                "Audit logging ENABLED" if audit_enabled else "Audit logging DISABLED"
            )
            + (f"; {len(weaknesses)} policy weakness(es)" if weaknesses else ""),
        )


def _extract_flags(manifest_text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for flag in _FLAGS:
        m = re.search(rf"--{re.escape(flag)}[= ]([^\s\"']+)", manifest_text)
        if m:
            out[flag] = m.group(1)
    return out
