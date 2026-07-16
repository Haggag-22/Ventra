"""k8s_kubelet_logs — the node's own account of pod admission and container lifecycle.

``journalctl -u kubelet`` (or ``/var/log/kubelet.log`` on non-systemd nodes) records pod
admission, image pulls, container start/stop, and volume mounts. Cross-checking it against the
API-server audit log is powerful: a divergence between what the API server was asked to do and
what the kubelet actually did is a strong tampering signal.
"""

from __future__ import annotations

from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector


class KubeletLogsCollector(NodePlaneCollector):
    name = "k8s_kubelet_logs"
    priority = 2
    description = "kubelet journal/log: pod admission, image pulls, container lifecycle."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        result = collect_unit(
            node, "kubelet", fallback_files=("/var/log/kubelet.log", "/var/log/syslog")
        )
        records = result["records"]
        for rec in records:
            nc.stamp(rec)

        files = []
        if records:
            files.append(self.write_jsonl(records, "kubelet.jsonl.gz"))
        files.append(
            self.write_json({"source": result["source"], "node": nc.to_dict()}, "config.json")
        )
        self.write_meta({"source": self.name, "records": len(records)})

        if not result["available"]:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                files=files,
                gaps=[(self.name, GapReason.NOT_PRESENT, result["note"])],
                notes=result["note"],
            )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED if records else SourceStatus.EMPTY,
            files=files,
            record_count=len(records),
            notes=result["note"],
        )
