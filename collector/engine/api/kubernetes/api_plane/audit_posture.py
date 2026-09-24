"""k8s_audit_posture — is API-server audit logging even on?

The most common finding in a Kubernetes IR is "there is no audit log." That must be a
first-class, prominently-surfaced result, not a silent absence. This collector reports
whether ``--audit-log-path`` and ``--audit-policy-file`` are set, what the policy actually
logs, the rotation settings that cap how far back the log reaches, and whether a webhook
backend sends events off the node.

The flags are read through the node plane from whichever source this distribution uses: a
kubeadm or RKE2 static pod manifest, ``/etc/rancher/k3s/config.yaml``, the k3s or RKE2 server
unit's ``ExecStart`` line, or ``/var/snap/microk8s/current/args/kube-apiserver``. When no flag
source is readable but an audit log file is already on disk (the common k3s case), posture is
still reported from that file rather than being abandoned. With neither, the collector says
what it looked at and degrades to a clear gap instead of guessing.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.analysis import audit_policy_weaknesses
from ..common.apiserver_flags import read_apiserver_flags
from ..common.distro import detect_distro

# Searched when no flag source names a path: an audit file already on disk proves auditing is
# on even where the flags cannot be read (a default k3s install writes the first of these).
_DEFAULT_AUDIT_PATHS = (
    "/var/log/kubernetes/audit/audit.log",
    "/var/log/kube-apiserver-audit.log",
    "/var/log/kubernetes/kube-apiserver-audit.log",
    "/var/log/apiserver/audit.log",
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

        if node is None:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "No node plane available, so kube-apiserver flags could not be read from "
                    "disk and audit posture is undetermined. Run the node-plane collector on a "
                    "control-plane or server node to confirm.",
                )
            )
            self.write_json({"determined": False, "reason": "node plane unavailable"}, "config.json")
            self.write_meta({"source": self.name, "determined": False})
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps,
                notes="Audit posture undetermined (node plane not reachable).",
            )

        distro = detect_distro(node)
        resolved = read_apiserver_flags(node, distro)
        flags = dict(resolved.flags)

        # No flag source on this node: a log file already on disk still proves auditing is on.
        audit_file_on_disk = ""
        if not flags.get("audit-log-path"):
            for candidate in _DEFAULT_AUDIT_PATHS:
                try:
                    if node.exists(candidate) and not node.is_dir(candidate):
                        audit_file_on_disk = candidate
                        break
                except Exception:  # noqa: BLE001 - an unreadable candidate is not fatal
                    continue

        log_backend = bool(flags.get("audit-log-path")) or bool(audit_file_on_disk)
        webhook = bool(flags.get("audit-webhook-config-file"))
        audit_enabled = log_backend or webhook
        policy_path = flags.get("audit-policy-file", "")

        if not resolved.determined and not audit_file_on_disk:
            # Nothing to read at all. Say what was inspected instead of claiming auditing off.
            searched = ", ".join(resolved.searched) or "no candidate paths for this layout"
            detail = (
                f"No kube-apiserver flag source is readable on this {distro.family} "
                f"{distro.role} node and no audit log file was found, so audit posture is "
                f"UNDETERMINED rather than known-off. Looked at: {searched}; "
                f"{', '.join(_DEFAULT_AUDIT_PATHS)}. Run this on a control-plane or server "
                "node, or check the API server's flags directly."
            )
            gaps.append((self.name, GapReason.NOT_PRESENT, detail))
            self.write_json(
                {
                    "determined": False,
                    "distro": distro.to_dict(),
                    "flag_resolution": resolved.to_dict(),
                    "audit_paths_searched": list(_DEFAULT_AUDIT_PATHS),
                    "reason": "no flag source and no audit file on this node",
                },
                "config.json",
            )
            self.write_meta({"source": self.name, "determined": False, "distro": distro.family})
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps,
                notes=f"Audit posture undetermined on this {distro.family} {distro.role} node.",
            )

        policy: dict[str, Any] = {}
        weaknesses: list[str] = []
        if policy_path and node.exists(policy_path):
            try:
                import yaml  # noqa: PLC0415

                policy = yaml.safe_load(node.read_text(policy_path)) or {}
                weaknesses = audit_policy_weaknesses(policy)
            except Exception as exc:  # noqa: BLE001
                gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"policy parse: {exc}"))

        rotation = _rotation_posture(flags)

        if not audit_enabled:
            gaps.append(
                (
                    self.name,
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "CRITICAL: API-server audit logging is DISABLED (no --audit-log-path and "
                    "no --audit-webhook-config-file in "
                    f"{', '.join(resolved.evidence) or 'the resolved flag sources'}, and no "
                    "audit log file on disk). There is no record of who did what in this "
                    "cluster: no pods/exec, no secret reads, no RBAC changes. This is the "
                    "single most important gap in the report. See k8s_apiserver_audit.",
                )
            )
        else:
            if webhook and not log_backend:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        "Audit events go to a WEBHOOK backend only "
                        f"(--audit-webhook-config-file={flags['audit-webhook-config-file']}). "
                        "No audit file is written on the control-plane node, so "
                        "k8s_apiserver_audit cannot collect it. The record lives in the "
                        "external sink; collect it from there.",
                    )
                )
            if not policy_path and resolved.determined:
                gaps.append(
                    (
                        self.name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "Audit logging is enabled but no --audit-policy-file is set; without a "
                        "policy the API server audits nothing at RequestResponse level.",
                    )
                )
            elif not policy_path and audit_file_on_disk:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"An audit log exists at {audit_file_on_disk} but this "
                        f"{distro.family} node exposes no kube-apiserver flag source, so the "
                        "audit policy could not be read. The log is collectable; what it was "
                        "configured to capture is unconfirmed.",
                    )
                )
            elif not policy:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"Audit policy file {policy_path} is referenced but could not be read "
                        "from this node, so what the cluster actually audits is unconfirmed.",
                    )
                )
            if weaknesses:
                gaps.append(
                    (
                        self.name,
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "Audit logging is enabled but the policy is weak: " + "; ".join(weaknesses),
                    )
                )
            for issue in rotation["issues"]:
                gaps.append((self.name, GapReason.LOGGING_NOT_CONFIGURED, issue))

        config = {
            "audit_enabled": audit_enabled,
            "log_backend": log_backend,
            "audit_log_on_disk": audit_file_on_disk,
            "distro": distro.to_dict(),
            "flag_resolution": resolved.to_dict(),
            "flags": flags,
            "audit_policy_file": policy_path,
            "audit_policy": policy,
            "policy_weaknesses": weaknesses,
            "webhook_backend": webhook,
            "rotation": rotation,
        }
        files = [self.write_json(config, "config.json")]
        self.write_meta(
            {
                "source": self.name,
                "audit_enabled": audit_enabled,
                "weaknesses": len(weaknesses),
                "distro": distro.family,
            }
        )
        status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=1,
            gaps=gaps,
            notes=("Audit logging ENABLED" if audit_enabled else "Audit logging DISABLED")
            + (f"; {len(weaknesses)} policy weakness(es)" if weaknesses else ""),
        )


def _rotation_posture(flags: dict[str, str]) -> dict[str, Any]:
    """Retention settings decide how far back the audit log can take an investigation.

    kube-apiserver treats ``0``/unset as *no limit* for both ``--audit-log-maxage`` and
    ``--audit-log-maxbackup``, so an absent flag is the permissive case, not a gap. Only a
    small positive value caps the investigable window, and that is what gets reported.
    """
    out: dict[str, Any] = {"issues": []}
    for flag in ("audit-log-maxage", "audit-log-maxbackup", "audit-log-maxsize"):
        raw = flags.get(flag)
        out[flag] = int(raw) if raw and raw.isdigit() else (raw or None)

    if not flags.get("audit-log-path"):
        return out

    maxage = out.get("audit-log-maxage")
    maxbackup = out.get("audit-log-maxbackup")
    out["age_limited"] = isinstance(maxage, int) and maxage > 0
    out["backup_limited"] = isinstance(maxbackup, int) and maxbackup > 0

    if out["age_limited"] and maxage < 30:
        out["issues"].append(
            f"--audit-log-maxage={maxage} day(s): audit history older than that has already "
            "been deleted, which caps how far back this investigation can reach."
        )
    if out["backup_limited"] and maxbackup <= 2:
        out["issues"].append(
            f"--audit-log-maxbackup={maxbackup}: only {maxbackup} rotated file(s) are kept "
            f"alongside the active log"
            + (
                f" at --audit-log-maxsize={out['audit-log-maxsize']}MB each"
                if isinstance(out.get("audit-log-maxsize"), int)
                else ""
            )
            + " — on a busy cluster that can be minutes of history."
        )
    return out
