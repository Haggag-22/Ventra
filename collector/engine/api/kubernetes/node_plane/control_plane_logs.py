"""k8s_control_plane_logs — static-pod logs + manifests (on-prem exclusive).

Collects logs for kube-apiserver, kube-scheduler, and kube-controller-manager static pods,
and — critically — the static pod **manifests** under ``/etc/kubernetes/manifests/``. An
attacker who writes a file there gets a privileged pod on the control plane with no API call
and therefore no audit-log entry. We hash every manifest so tampering is detectable.
"""

from __future__ import annotations

from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile

from ..common.nodebase import NodePlaneCollector

_MANIFEST_DIR = "/etc/kubernetes/manifests"
_STATIC_POD_GLOBS = (
    "/var/log/pods/kube-system_kube-apiserver-*/*/*.log",
    "/var/log/pods/kube-system_kube-scheduler-*/*/*.log",
    "/var/log/pods/kube-system_kube-controller-manager-*/*/*.log",
)
_EXPECTED_MANIFESTS = frozenset(
    {"kube-apiserver.yaml", "kube-scheduler.yaml", "kube-controller-manager.yaml", "etcd.yaml"}
)


class ControlPlaneLogsCollector(NodePlaneCollector):
    name = "k8s_control_plane_logs"
    priority = 2
    description = "Control-plane static-pod logs + manifests with tamper hashing (on-prem)."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        gaps: list[tuple[str, GapReason, str]] = []
        files: list[WrittenFile] = []

        if not node.is_dir(_MANIFEST_DIR) and not node.is_dir("/var/log/pods"):
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        "Neither /etc/kubernetes/manifests nor /var/log/pods present — this is "
                        "not a control-plane node (run the collector on a control-plane node).",
                    )
                ],
                notes="Not a control-plane node.",
            )

        # Static pod manifests (durable evidence; hash for tamper detection).
        manifests: list[dict[str, Any]] = []
        unexpected: list[str] = []
        for path in node.iter_glob(f"{_MANIFEST_DIR}/*"):
            if not path.is_file():
                continue
            host_path = "/" + path.relative_to(node.root).as_posix()
            wf = self.copy_node_file(host_path, f"manifests/{path.name}")
            if wf is None:
                continue
            files.append(wf)
            entry = {"path": host_path, "name": path.name, "sha256": wf.sha256, "bytes": wf.bytes}
            manifests.append(entry)
            if path.name not in _EXPECTED_MANIFESTS:
                unexpected.append(path.name)

        if unexpected:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    f"Unexpected static pod manifest(s) in {_MANIFEST_DIR}: {', '.join(unexpected)}. "
                    "A manifest here creates a privileged control-plane pod with NO audit entry — "
                    "review and diff against known-good content.",
                )
            )

        # Static pod logs.
        log_count = 0
        for glob in _STATIC_POD_GLOBS:
            for path in node.iter_glob(glob):
                host_path = "/" + path.relative_to(node.root).as_posix()
                dest = f"logs/{host_path.lstrip('/').replace('/', '__')}"
                wf = self.capture_path(path, dest)
                if wf is not None:
                    files.append(wf)
                    log_count += 1

        files.append(
            self.write_json(
                {
                    "manifests": manifests,
                    "unexpected_manifests": unexpected,
                    "static_pod_logs": log_count,
                    "node": nc.to_dict(),
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "manifests": len(manifests), "logs": log_count})

        collected = len(manifests) + log_count
        status = SourceStatus.PARTIAL if (gaps and collected) else (
            SourceStatus.COLLECTED if collected else SourceStatus.EMPTY
        )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=collected,
            gaps=gaps,
            notes=f"{len(manifests)} manifest(s), {log_count} static-pod log file(s); "
            f"{len(unexpected)} unexpected manifest(s).",
        )
