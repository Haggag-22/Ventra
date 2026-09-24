"""k8s_runtime_logs — CRI journal + live CRI state snapshot.

CRI (containerd / CRI-O) records image pulls (including from unexpected registries), container
lifecycle, and CRI errors, and its live state shows what is running right now and where each
container's storage lives.

Both halves are resolved independently, because on several distributions they come from
different places:

* **Journal** — ``journalctl -u containerd`` / ``-u crio`` on kubeadm. k3s, RKE2 and microk8s
  embed containerd inside the node agent, so there is no ``containerd`` unit to read and the
  collector falls back to the distro's own unit (``k3s``, ``k3s-agent``, ``rke2-agent``, the
  kubelite snap daemon), marking the source as shared with the other collectors that quote
  the same journal.
* **Live state** — ``crictl ps -a`` / ``images`` / ``pods`` plus ``crictl inspect`` per
  container, which work off the CRI socket regardless of how the runtime is supervised.
  Embedded sockets (``/run/k3s/containerd/containerd.sock``,
  ``/var/snap/microk8s/common/run/containerd.sock``) are probed alongside the standard path.

A missing journal unit is therefore not a failure when the socket answers: the collector
reports what it got from each half rather than treating the kubeadm layout as the only one.
"""

from __future__ import annotations

import json
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import param_int

from ..common.distro import node_agent_units
from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector

# ``crictl inspect`` is one exec per container; cap it so a 200-container node cannot stall
# a run. Raise with the ``max_inspect`` artifact parameter when a node needs full coverage.
_DEFAULT_MAX_INSPECT = 100


class RuntimeLogsCollector(NodePlaneCollector):
    name = "k8s_runtime_logs"
    priority = 2
    description = (
        "CRI logs (containerd, CRI-O, or the distro agent unit that embeds them) plus a live "
        "crictl state snapshot."
    )
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        distro = self.distro()
        runtime = node.runtime_info()
        attempted: list[str] = []

        result, unit, shared = self._resolve_journal(runtime, attempted)
        records = result["records"]
        for rec in records:
            nc.stamp(rec)
            distro.stamp(rec)
            rec["_ventra_runtime_unit"] = unit

        snapshot = self._live_state(node)
        inspects = self._inspect_containers(node, snapshot)

        files = []
        if records:
            files.append(self.write_jsonl(records, "runtime.jsonl.gz"))
        files.append(self.write_json(snapshot, "live_state.json"))
        if inspects:
            files.append(self.write_jsonl(inspects, "container_inspect.jsonl.gz"))
        files.append(
            self.write_json(
                {
                    "runtime": runtime.to_dict(),
                    "unit": unit,
                    "shared_unit": shared,
                    "distro": distro.to_dict(),
                    "source": result["source"],
                    "journal_available": bool(result["available"] and records),
                    "live_state_available": bool(snapshot.get("available")),
                    "containers_inspected": len(inspects),
                    "attempted": attempted,
                    "node": nc.to_dict(),
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "records": len(records), "distro": distro.family})

        gaps: list[tuple[str, GapReason, str]] = []
        live_ok = bool(snapshot.get("available"))
        if not records:
            # A missing journal unit is only a gap when the live socket did not answer
            # either; on an embedded runtime one half routinely carries the evidence.
            tried = "; ".join(attempted) or "no candidate units for this layout"
            if live_ok:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"No container-runtime journal on this {distro.family} node, but live "
                        f"runtime state was captured from the CRI socket ({runtime.socket or 'crictl'}). "
                        f"Historical image pulls and container lifecycle are unavailable. "
                        f"Tried: {tried}",
                    )
                )
            else:
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"Neither a container-runtime journal nor live CRI state could be read "
                        f"on this {distro.family} node. Mount the host journal and the CRI "
                        f"socket into the collector pod. Tried: {tried}",
                    )
                )
        if runtime.runtime == "unknown":
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "No container runtime detected on this node: no CRI socket and no known "
                    "storage root, so live runtime state could not be snapshotted.",
                )
            )
        status = SourceStatus.COLLECTED if (records or live_ok) else SourceStatus.EMPTY
        if gaps and status == SourceStatus.COLLECTED:
            status = SourceStatus.PARTIAL
        note = f"{result['note']} {len(inspects)} container(s) inspected."
        if shared:
            note += (
                f" containerd is embedded in {distro.family}, so these records come from the "
                f"{unit} unit rather than a containerd unit of its own."
            )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=note,
        )

    def _resolve_journal(self, runtime: Any, attempted: list[str]) -> tuple[dict[str, Any], str, bool]:
        """The runtime's own unit, then the distro unit that embeds it."""
        node = self.node
        distro = self.distro()
        unit = {"containerd": "containerd", "cri-o": "crio", "docker": "docker"}.get(
            runtime.runtime, "containerd"
        )
        attempted.append(f"journalctl -u {unit}")
        result = collect_unit(node, unit, fallback_files=(f"/var/log/{unit}.log", "/var/log/syslog"))
        if result["available"] and result["records"]:
            return result, unit, False

        for candidate_unit in node_agent_units(distro) or distro.server_units:
            attempted.append(f"journalctl -u {candidate_unit}")
            candidate = collect_unit(node, candidate_unit)
            if candidate["available"] and candidate["records"]:
                return candidate, candidate_unit, True
        return result, unit, False

    def _live_state(self, node: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"available": False}
        if not node.have("crictl"):
            out["note"] = "crictl not available on node."
            return out
        for label, args in (
            ("containers", node.crictl("ps", "-a", "-o", "json")),
            ("images", node.crictl("images", "-o", "json")),
            ("pods", node.crictl("pods", "-o", "json")),
        ):
            rc, stdout, _ = node.run(args)
            if rc == 0 and stdout.strip():
                try:
                    out[label] = json.loads(stdout)
                    out["available"] = True
                except json.JSONDecodeError:
                    out[label] = {"_raw": stdout}
        return out

    def _inspect_containers(self, node: Any, snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        """``crictl inspect`` per container — the runtime spec, mounts, and storage paths.

        This is where the overlay upper-dir lives for implicated containers; analysts can target a
        container without any hardcoded per-runtime path.
        """
        if not snapshot.get("available") or not node.have("crictl"):
            return []
        containers = snapshot.get("containers") or {}
        rows = containers.get("containers") if isinstance(containers, dict) else None
        if not rows:
            return []
        cap = param_int(self.artifact_params(), "max_inspect", default=_DEFAULT_MAX_INSPECT)
        cap = cap if cap and cap > 0 else _DEFAULT_MAX_INSPECT
        nc = self.node_context()

        out: list[dict[str, Any]] = []
        for container in rows[:cap]:
            cid = str((container or {}).get("id", ""))
            if not cid:
                continue
            rc, stdout, err = node.run(node.crictl("inspect", cid), timeout=60)
            rec: dict[str, Any] = {"container_id": cid}
            labels = (container or {}).get("labels") or {}
            rec["pod"] = labels.get("io.kubernetes.pod.name", "")
            rec["namespace"] = labels.get("io.kubernetes.pod.namespace", "")
            rec["container"] = labels.get("io.kubernetes.container.name", "")
            if rc == 0 and stdout.strip():
                try:
                    rec["inspect"] = json.loads(stdout)
                except json.JSONDecodeError:
                    rec["inspect"] = {"_raw": stdout}
            else:
                rec["error"] = err.strip() or f"crictl inspect exited {rc}"
            nc.stamp(rec)
            out.append(rec)
        if len(rows) > cap:
            out.append(
                nc.stamp(
                    {
                        "_ventra_note": f"inspect capped at {cap} of {len(rows)} container(s); "
                        "raise the max_inspect parameter for full coverage."
                    }
                )
            )
        return out
