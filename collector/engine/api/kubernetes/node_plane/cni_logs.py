"""k8s_cni_logs — CNI plugin logs and flow evidence.

Detects the network plugin (Calico, Cilium, Flannel, Weave), then collects its logs and, where
the plugin supports it, flow logs: the primary evidence for lateral movement and exfiltration.

Detection reads the CNI configuration directory, which is not in the same place on every
distribution. kubeadm uses ``/etc/cni/net.d``; k3s and RKE2 keep their own copy under
``/var/lib/rancher/<distro>/agent/etc/cni/net.d`` (a default k3s install ships flannel there);
microk8s uses ``/var/snap/microk8s/current/args/cni-network``. All of them are probed, so a
plugin is not missed just because the node is not kubeadm.
"""

from __future__ import annotations

from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile

from ..common.nodebase import NodePlaneCollector

# CNI configuration directories, by distribution. A plugin's config file lands in one of
# these, so detection globs are probed against every one.
_CNI_CONF_DIRS = (
    "/etc/cni/net.d",
    "/var/lib/rancher/k3s/agent/etc/cni/net.d",
    "/var/lib/rancher/rke2/agent/etc/cni/net.d",
    "/var/snap/microk8s/current/args/cni-network",
)

# plugin -> (detection file patterns relative to a CNI conf dir, extra probes, log globs)
_PLUGINS: dict[str, dict[str, tuple[str, ...]]] = {
    "calico": {
        "conf": ("*calico*",),
        "detect": ("/var/log/calico",),
        "logs": ("/var/log/calico/**/*.log", "/var/log/calico/*.log"),
    },
    "cilium": {
        "conf": ("*cilium*",),
        "detect": ("/var/run/cilium",),
        "logs": ("/var/log/cilium/*.log", "/var/run/cilium/*.log"),
    },
    "flannel": {
        "conf": ("*flannel*",),
        "detect": ("/var/lib/rancher/k3s/agent/etc/flannel",),
        "logs": ("/var/log/flannel/*.log",),
    },
    "weave": {
        "conf": ("*weave*",),
        "detect": ("/var/log/weave",),
        "logs": ("/var/log/weave/*.log",),
    },
}


class CniLogsCollector(NodePlaneCollector):
    name = "k8s_cni_logs"
    priority = 2
    description = "CNI plugin detection + logs (Calico/Cilium/Flannel/Weave) and flow evidence."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        gaps: list[tuple[str, GapReason, str]] = []
        files: list[WrittenFile] = []

        detected = self._detect(node)
        collected = 0
        for plugin in detected:
            for glob in _PLUGINS[plugin]["logs"]:
                for path in node.iter_glob(glob):
                    if not path.is_file():
                        continue
                    host_path = "/" + path.relative_to(node.root).as_posix()
                    dest = f"{plugin}/{host_path.lstrip('/').replace('/', '__')}"
                    wf = self.capture_path(path, dest)
                    if wf is not None:
                        files.append(wf)
                        collected += 1

        # Cilium: capture Hubble flows if the CLI is present.
        hubble = self._hubble_flows(node)
        if hubble is not None:
            files.append(hubble)
            collected += 1

        files.append(
            self.write_json(
                {
                    "detected_plugins": detected,
                    "log_files": collected,
                    "cni_conf_dirs_searched": list(_CNI_CONF_DIRS),
                    "distro": self.distro().to_dict(),
                    "node": nc.to_dict(),
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "plugins": detected, "log_files": collected})

        if not detected:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "No known CNI plugin (Calico, Cilium, Flannel, Weave) was detected. "
                    f"Searched: {', '.join(_CNI_CONF_DIRS)}.",
                )
            )
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                files=files,
                gaps=gaps,
                notes="No CNI plugin detected.",
            )
        status = SourceStatus.COLLECTED if collected else SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=collected,
            gaps=gaps,
            notes=f"CNI: {', '.join(detected)}; {collected} log file(s).",
        )

    def _detect(self, node: Any) -> list[str]:
        """Which plugins are configured, looking in every distro's CNI config directory."""
        found: list[str] = []
        for plugin, cfg in _PLUGINS.items():
            probes = [
                f"{conf_dir}/{pattern}" for conf_dir in _CNI_CONF_DIRS for pattern in cfg.get("conf", ())
            ]
            probes.extend(cfg.get("detect", ()))
            for probe in probes:
                if node.iter_glob(probe) or node.exists(probe):
                    found.append(plugin)
                    break
        return found

    def _hubble_flows(self, node: Any) -> WrittenFile | None:
        if not node.have("hubble"):
            return None
        rc, out, _ = node.run(["hubble", "observe", "--last", "5000", "-o", "json"], timeout=120)
        if rc != 0 or not out.strip():
            return None
        return self.write_node_bytes(out.encode("utf-8"), "cilium/hubble-flows.jsonl")
