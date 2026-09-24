"""k8s_container_logs — container logs read from the node.

Reads ``/var/log/pods/<namespace>_<pod>_<uid>/<container>/*.log`` directly. This is more
complete than the API: it includes rotated logs and logs for pods that no longer exist.
``/var/log/containers/*.log`` are symlinks into the pods tree — we follow them but never
collect the same content twice.
"""

from __future__ import annotations

from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile
from collector.lib.params import param_strings

from ..common.nodebase import NodePlaneCollector

_PODS_LOG_ROOT = "/var/log/pods"
# ``*.log`` plus the kubelet's rotated forms (``0.log.20260101-120000.gz``, ``0.log.1``).
_LOG_GLOBS = (f"{_PODS_LOG_ROOT}/*/*/*.log", f"{_PODS_LOG_ROOT}/*/*/*.log.*")


class ContainerLogsCollector(NodePlaneCollector):
    name = "k8s_container_logs"
    priority = 1
    description = "Container logs from the node filesystem (rotated + dead-pod logs)."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        gaps: list[tuple[str, GapReason, str]] = []
        nc = self.node_context()

        if not node.is_dir(_PODS_LOG_ROOT):
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.NOT_PRESENT, f"{_PODS_LOG_ROOT} not present on node.")],
                notes="No pod log directory on node.",
            )

        ns_filter = [n.lower() for n in param_strings(self.artifact_params(), "namespaces")]
        files: list[WrittenFile] = []
        index: list[dict[str, Any]] = []
        collected = 0

        seen: set[str] = set()
        rotated = 0
        for glob in _LOG_GLOBS:
            for log_path in node.iter_glob(glob):
                host_path = "/" + log_path.relative_to(node.root).as_posix()
                if host_path in seen:
                    continue
                seen.add(host_path)
                meta = _parse_pod_log_path(host_path)
                if ns_filter and meta.get("namespace", "").lower() not in ns_filter:
                    continue
                wf = self.capture_path(log_path, f"logs/{_flatten_name(host_path)}")
                if wf is None:
                    continue
                collected += 1
                if not host_path.endswith(".log"):
                    rotated += 1
                files.append(wf)
                index.append(
                    {
                        **meta,
                        "host_path": host_path,
                        "archive_path": wf.path,
                        "sha256": wf.sha256,
                        "rotated": not host_path.endswith(".log"),
                    }
                )

        files.append(
            self.write_json(
                {
                    "logs": index,
                    "rotated_logs": rotated,
                    "note": "/var/log/containers symlinks were not traversed: they point into "
                    "this same tree, which is walked directly.",
                    "distro": self.distro().to_dict(),
                    "node": nc.to_dict(),
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "logs": collected, "rotated": rotated})

        status = SourceStatus.COLLECTED if collected else SourceStatus.EMPTY
        if not collected and not gaps:
            gaps.append((self.name, GapReason.NOT_PRESENT, "No container logs found on node."))
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=collected,
            gaps=gaps,
            notes=f"{collected} container log file(s) ({rotated} rotated) from {node.hostname() or 'node'}.",
        )


def _parse_pod_log_path(host_path: str) -> dict[str, str]:
    # /var/log/pods/<namespace>_<pod>_<uid>/<container>/<n>.log
    parts = host_path.split("/")
    try:
        pod_dir = parts[parts.index("pods") + 1]
        container = parts[parts.index("pods") + 2]
    except (ValueError, IndexError):
        return {}
    ns, _, rest = pod_dir.partition("_")
    pod, _, uid = rest.rpartition("_")
    return {"namespace": ns, "pod": pod, "uid": uid, "container": container}


def _flatten_name(host_path: str) -> str:
    return host_path.lstrip("/").replace("/", "__")
