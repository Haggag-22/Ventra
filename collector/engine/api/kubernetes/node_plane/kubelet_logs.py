"""k8s_kubelet_logs — the node's own account of pod admission and container lifecycle.

The kubelet records pod admission, image pulls, container start/stop, and volume mounts.
Cross-checking it against the API-server audit log is powerful: a divergence between what the
API server was asked to do and what the kubelet actually did is a strong tampering signal.

Where those records live depends on the distribution, so the collector works down an ordered
list and reports which source answered:

1. ``journalctl -u kubelet`` — kubeadm and anything else running kubelet as its own unit;
2. ``/var/log/kubelet.log`` or the syslog, for non-systemd nodes;
3. the distribution's node-agent unit, because several distros do not run a separate kubelet
   process at all: on k3s it lives inside ``k3s-agent`` (worker) or ``k3s`` (server), on RKE2
   inside ``rke2-agent`` / ``rke2-server``, and on microk8s inside the kubelite snap daemon.

When the kubelet's records come from a merged unit, that unit also carries the control plane
or the container runtime, so ``config.json`` says which unit answered and marks the source as
shared. That way an analyst reading two collectors that quote the same journal knows why, and
does not read one node's activity as two independent confirmations.
"""

from __future__ import annotations

from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.distro import node_agent_units
from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector

_FALLBACK_FILES = ("/var/log/kubelet.log", "/var/log/syslog")


class KubeletLogsCollector(NodePlaneCollector):
    name = "k8s_kubelet_logs"
    priority = 2
    description = (
        "kubelet journal or log: pod admission, image pulls, container lifecycle, including "
        "distros where the kubelet is embedded in the node agent."
    )
    required_actions = ()

    def collect(self) -> SourceResult:
        nc = self.node_context()
        distro = self.distro()
        attempted: list[str] = []

        result, unit, shared = self._resolve(attempted)
        records: list[dict[str, Any]] = result["records"]
        for rec in records:
            nc.stamp(rec)
            distro.stamp(rec)
            rec["_ventra_kubelet_unit"] = unit

        files = []
        if records:
            files.append(self.write_jsonl(records, "kubelet.jsonl.gz"))

        note = result["note"]
        if shared:
            note += (
                f" The kubelet has no unit of its own on {distro.family}; these records come "
                f"from the {unit} unit, which also carries the control plane and container "
                "runtime on this node."
            )
        files.append(
            self.write_json(
                {
                    "source": result["source"],
                    "unit": unit,
                    "shared_unit": shared,
                    "distro": distro.to_dict(),
                    "attempted": attempted,
                    "node": nc.to_dict(),
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "records": len(records), "distro": distro.family, "unit": unit})

        if not result["available"]:
            tried = "; ".join(attempted) or "no candidate units for this layout"
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                files=files,
                gaps=[
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"No kubelet records on this {distro.family} node. Tried: {tried}. "
                        "The journal may not be mounted into the collector pod (mount "
                        "/var/log/journal and /run/log/journal), or this node may not run a "
                        "kubelet at all.",
                    )
                ],
                notes=note,
            )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED if records else SourceStatus.EMPTY,
            files=files,
            record_count=len(records),
            notes=note,
        )

    def _resolve(self, attempted: list[str]) -> tuple[dict[str, Any], str, bool]:
        """First source that answers: kubelet unit, log file, then the distro agent unit."""
        node = self.node
        distro = self.distro()

        attempted.append("journalctl -u kubelet")
        result = collect_unit(node, "kubelet", fallback_files=_FALLBACK_FILES)
        if result["available"] and result["records"]:
            return result, "kubelet", False
        attempted.extend(f"file:{path}" for path in _FALLBACK_FILES)

        for unit in node_agent_units(distro):
            attempted.append(f"journalctl -u {unit}")
            candidate = collect_unit(node, unit)
            if candidate["available"] and candidate["records"]:
                # Merged distros run kubelet inside the same process as everything else.
                return candidate, unit, distro.merged_control_plane
        return result, "kubelet", False
