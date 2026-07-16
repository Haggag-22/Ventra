"""k8s_pod_logs — container stdout/stderr via the API (kubeconfig-only path).

Pulls ``pods/log`` for every container, including ``--previous`` for crashed/restarted
containers (the attacker's container may already have died). This only returns logs the
kubelet still has on disk — rotated logs are gone; the node-plane ``k8s_container_logs`` is
the more complete source. This one exists because it works with nothing but a kubeconfig.
"""

from __future__ import annotations

from typing import Any

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeNotFound
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import param_strings


class PodLogsCollector(Collector):
    name = "k8s_pod_logs"
    priority = 1
    plane = "api"
    description = "Container stdout/stderr through the API server (incl. previous containers)."
    required_actions = ("get pods", "list pods", "get pods/log")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []

        try:
            pods = cf.list_pods()
        except KubeAccessDenied as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.ACCESS_DENIED, exc.message)],
            )
        except KubeNotFound as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.NOT_PRESENT, exc.message)],
            )

        ns_filter = [n.lower() for n in param_strings(self.artifact_params(), "namespaces")]
        pod_filter = [p.lower() for p in param_strings(self.artifact_params(), "pods")]

        records: list[dict[str, Any]] = []
        containers_read = 0
        for pod in pods:
            meta = pod.get("metadata") or {}
            ns = str(meta.get("namespace", ""))
            name = str(meta.get("name", ""))
            if ns_filter and ns.lower() not in ns_filter:
                continue
            if pod_filter and name.lower() not in pod_filter:
                continue
            for container in _container_names(pod):
                for previous in (False, True):
                    text = self._read_log(cf, ns, name, container, previous, gaps)
                    if not text:
                        continue
                    containers_read += 1
                    records.append(
                        {
                            "namespace": ns,
                            "pod": name,
                            "container": container,
                            "previous": previous,
                            "log": text,
                            "_ventra_cluster": self.ctx.account_id,
                        }
                    )

        files = []
        if records:
            files.append(self.write_jsonl(records, "pod_logs.jsonl.gz"))
        files.append(
            self.write_json(
                {"pods": len(pods), "log_streams": len(records)}, "config.json"
            )
        )
        self.write_meta({"source": self.name, "log_streams": len(records)})

        if not records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
        else:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} log stream(s) from {len(pods)} pod(s).",
        )

    def _read_log(
        self,
        cf: Any,
        ns: str,
        pod: str,
        container: str,
        previous: bool,
        gaps: list[tuple[str, GapReason, str]],
    ) -> str:
        try:
            return cf.read_pod_log(ns, pod, container, previous=previous) or ""
        except KubeAccessDenied as exc:
            gaps.append((self.name, GapReason.ACCESS_DENIED, f"{ns}/{pod}/{container}: {exc.message}"))
            return ""
        except KubeNotFound:
            # "previous" logs commonly 404 when the container never restarted — not a gap.
            return ""
        except Exception:  # noqa: BLE001 - a single unreadable stream is not fatal
            return ""


def _container_names(pod: dict[str, Any]) -> list[str]:
    spec = pod.get("spec") or {}
    names: list[str] = []
    keys = (
        "containers",
        "init_containers",
        "initContainers",
        "ephemeral_containers",
        "ephemeralContainers",
    )
    for key in keys:
        for c in spec.get(key) or []:
            n = c.get("name")
            if n:
                names.append(str(n))
    return names
