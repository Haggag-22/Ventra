"""NodeContext — the node provenance stamped onto every node-plane record.

On-prem we collect from many nodes. An analyst must always be able to trace a record back
to the node it came from and the runtime that produced it, so every node-plane record carries
these ``_ventra_*`` fields (mirroring the ``_ventra_cluster`` / ``_ventra_region`` convention
the cloud collectors use).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class NodeContext:
    node_name: str = ""
    kernel: str = ""
    runtime: str = ""
    runtime_version: str = ""
    kubelet_version: str = ""
    cluster_id: str = ""

    def to_fields(self) -> dict[str, Any]:
        """The ``_ventra_*`` provenance fields merged into each node-plane record."""
        return {
            "_ventra_node": self.node_name,
            "_ventra_kernel": self.kernel,
            "_ventra_runtime": self.runtime,
            "_ventra_runtime_version": self.runtime_version,
            "_ventra_kubelet_version": self.kubelet_version,
            "_ventra_cluster": self.cluster_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_name": self.node_name,
            "kernel": self.kernel,
            "runtime": self.runtime,
            "runtime_version": self.runtime_version,
            "kubelet_version": self.kubelet_version,
            "cluster_id": self.cluster_id,
        }

    def stamp(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return ``record`` with node provenance fields added in place."""
        record.update(self.to_fields())
        return record


def build_node_context(node: Any, cluster_id: str = "") -> NodeContext:
    """Resolve a NodeContext from a :class:`NodeAccess`, tolerating missing facts."""
    runtime = node.runtime_info()
    return NodeContext(
        node_name=_safe(node.hostname),
        kernel=_safe(node.kernel),
        runtime=runtime.runtime,
        runtime_version=runtime.version,
        kubelet_version=_safe(node.kubelet_version),
        cluster_id=cluster_id,
    )


def _safe(fn: Any) -> str:
    try:
        return fn() or ""
    except Exception:  # noqa: BLE001 - provenance is best-effort, never fatal
        return ""
