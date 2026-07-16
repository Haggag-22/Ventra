"""k8s_runtime_logs — container-runtime journal + live runtime state snapshot.

``journalctl -u containerd`` / ``-u crio`` records image pulls (including from unexpected
registries), container lifecycle, and CRI errors. Also snapshots live state via
``crictl ps -a`` / ``images`` / ``pods`` so the analyst sees what is running right now.
"""

from __future__ import annotations

import json
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector


class RuntimeLogsCollector(NodePlaneCollector):
    name = "k8s_runtime_logs"
    priority = 2
    description = "Container-runtime journal (containerd/crio) + live crictl state snapshot."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        runtime = node.runtime_info()
        unit = {"containerd": "containerd", "cri-o": "crio", "docker": "docker"}.get(
            runtime.runtime, "containerd"
        )

        result = collect_unit(
            node, unit, fallback_files=(f"/var/log/{unit}.log", "/var/log/syslog")
        )
        records = result["records"]
        for rec in records:
            nc.stamp(rec)

        snapshot = self._live_state(node)

        files = []
        if records:
            files.append(self.write_jsonl(records, "runtime.jsonl.gz"))
        files.append(self.write_json(snapshot, "live_state.json"))
        files.append(
            self.write_json(
                {"runtime": runtime.to_dict(), "unit": unit, "source": result["source"]},
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "records": len(records)})

        gaps: list[tuple[str, GapReason, str]] = []
        if not result["available"]:
            gaps.append((self.name, GapReason.NOT_PRESENT, result["note"]))
        status = SourceStatus.COLLECTED if (records or snapshot.get("available")) else SourceStatus.EMPTY
        if gaps and status == SourceStatus.COLLECTED:
            status = SourceStatus.PARTIAL
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=result["note"],
        )

    def _live_state(self, node: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"available": False}
        if not node.have("crictl"):
            out["note"] = "crictl not available on node."
            return out
        for label, args in (
            ("containers", ["crictl", "ps", "-a", "-o", "json"]),
            ("images", ["crictl", "images", "-o", "json"]),
            ("pods", ["crictl", "pods", "-o", "json"]),
        ):
            rc, stdout, _ = node.run(args)
            if rc == 0 and stdout.strip():
                try:
                    out[label] = json.loads(stdout)
                    out["available"] = True
                except json.JSONDecodeError:
                    out[label] = {"_raw": stdout}
        return out
