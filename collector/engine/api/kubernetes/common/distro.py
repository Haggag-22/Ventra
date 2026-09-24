"""Kubernetes distribution detection for node-plane collectors.

Ventra's node-plane collectors were first written against **kubeadm**, where the control
plane runs as static pods under ``/etc/kubernetes/manifests`` and each component has its own
log tree and (sometimes) its own systemd unit. Real estates are not all kubeadm:

===========  ===========================================================================
Family       Control-plane reality on the node
===========  ===========================================================================
kubeadm      Static pods + ``/var/log/pods/kube-system_<component>-*`` + optional units
k3s          One merged process: ``journalctl -u k3s`` (server) / ``k3s-agent`` (worker).
             No separate apiserver / scheduler / controller-manager pods. State under
             ``/var/lib/rancher/k3s``; datastore is sqlite (kine) or embedded etcd.
rke2         ``rke2-server`` / ``rke2-agent`` units, static pods under
             ``/var/lib/rancher/rke2/agent/pod-manifests``, state under
             ``/var/lib/rancher/rke2``.
microk8s     snap units (``snap.microk8s.daemon-kubelite``), args under
             ``/var/snap/microk8s/current/args``, dqlite datastore.
unknown      Managed worker (EKS/GKE/AKS) or something we have not seen. There is no local
             control plane to read, so collectors must gap cleanly rather than fail.
===========  ===========================================================================

Detection is **filesystem-only and read-only**: it looks at well-known directories and at
systemd unit *files* rather than shelling out to ``systemctl``. That keeps it cheap enough to
run from several collectors, deterministic under a mocked node root in tests, and safe on a
node where the journal is unavailable.

Nothing here raises. An unrecognised node returns ``family="unknown"`` with whatever signals
were found, and the caller falls back to its own defaults.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any

# Where systemd unit files live. A unit file on disk is the reliable read-only signal that a
# service is installed, without asking systemd anything.
_UNIT_DIRS = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
)


@dataclass
class DistroInfo:
    """What Kubernetes distribution this node runs, and where its evidence lives."""

    family: str = "unknown"  # kubeadm | k3s | rke2 | microk8s | unknown
    role: str = "unknown"  # control-plane | server | worker | agent | unknown
    signals: list[str] = field(default_factory=list)
    # Units carrying the control plane (apiserver/scheduler/controller-manager), best first.
    server_units: list[str] = field(default_factory=list)
    # Units carrying the node agent (kubelet), best first.
    agent_units: list[str] = field(default_factory=list)
    # Files that may hold API-server flags when there is no static pod manifest.
    config_paths: list[str] = field(default_factory=list)
    # Distro state directories (datastore, TLS material).
    data_dirs: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def journal_units(self) -> list[str]:
        """Preferred units for this node, control plane first then the node agent."""
        out: list[str] = []
        for unit in self.server_units + self.agent_units:
            if unit not in out:
                out.append(unit)
        return out

    @property
    def merged_control_plane(self) -> bool:
        """True when apiserver, scheduler and controller-manager share one process/unit.

        On k3s, RKE2 and microk8s there is no per-component log to collect, so a collector
        must take the server journal once and say that it covers all three.
        """
        return self.family in ("k3s", "rke2", "microk8s")

    @property
    def is_control_plane(self) -> bool:
        return self.role in ("control-plane", "server")

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "role": self.role,
            "signals": list(self.signals),
            "server_units": list(self.server_units),
            "agent_units": list(self.agent_units),
            "config_paths": list(self.config_paths),
            "data_dirs": list(self.data_dirs),
            "merged_control_plane": self.merged_control_plane,
            "notes": self.notes,
        }

    def stamp(self, record: dict[str, Any]) -> dict[str, Any]:
        """Add distro provenance to a record, so an analyst sees why paths differ."""
        record["_ventra_distro"] = self.family
        record["_ventra_distro_role"] = self.role
        return record


# -- detection ------------------------------------------------------------------------------


def detect_distro(node: Any) -> DistroInfo:
    """Resolve the distribution once per run and cache it on the node accessor.

    Cached on the ``NodeAccess`` itself (the same object every node-plane collector shares
    through the client factory) so a run probes the filesystem once, not once per collector.
    """
    cached = getattr(node, "_ventra_distro_info", None)
    if isinstance(cached, DistroInfo):
        return cached
    info = _detect(node)
    # A node double in a test may not accept new attributes; detection still works, it just
    # repeats per collector.
    with contextlib.suppress(Exception):
        node._ventra_distro_info = info  # noqa: SLF001 - deliberate per-run cache
    return info


def _unit_installed(node: Any, unit: str) -> bool:
    """Is a systemd unit file present? (Read-only; never asks systemd.)"""
    name = unit if unit.endswith(".service") else f"{unit}.service"
    for directory in _UNIT_DIRS:
        try:
            if node.exists(f"{directory}/{name}"):
                return True
        except Exception:  # noqa: BLE001 - a missing mount must not break detection
            continue
    return False


def _dir(node: Any, path: str) -> bool:
    try:
        return bool(node.is_dir(path))
    except Exception:  # noqa: BLE001
        return False


def _file(node: Any, path: str) -> bool:
    try:
        return bool(node.exists(path))
    except Exception:  # noqa: BLE001
        return False


def _detect(node: Any) -> DistroInfo:
    signals: list[str] = []

    # --- k3s ---------------------------------------------------------------------------
    k3s_paths = [p for p in ("/etc/rancher/k3s", "/var/lib/rancher/k3s") if _dir(node, p)]
    k3s_units = [u for u in ("k3s", "k3s-agent") if _unit_installed(node, u)]
    if k3s_paths or k3s_units:
        signals.extend(f"path:{p}" for p in k3s_paths)
        signals.extend(f"unit:{u}" for u in k3s_units)
        server = (
            _dir(node, "/var/lib/rancher/k3s/server")
            or _unit_installed(node, "k3s")
            or _file(node, "/etc/rancher/k3s/config.yaml")
        )
        agent_only = _dir(node, "/var/lib/rancher/k3s/agent") and not server
        return DistroInfo(
            family="k3s",
            role="agent" if agent_only else ("server" if server else "unknown"),
            signals=signals,
            server_units=[] if agent_only else ["k3s"],
            agent_units=["k3s-agent", "k3s"] if agent_only else ["k3s"],
            config_paths=["/etc/rancher/k3s/config.yaml"],
            data_dirs=["/var/lib/rancher/k3s"],
            notes=(
                "k3s runs the API server, scheduler and controller-manager in one process, so "
                "there are no per-component static pods or log trees. Control-plane evidence "
                "is the k3s service journal."
            ),
        )

    # --- RKE2 --------------------------------------------------------------------------
    rke2_paths = [p for p in ("/etc/rancher/rke2", "/var/lib/rancher/rke2") if _dir(node, p)]
    rke2_units = [u for u in ("rke2-server", "rke2-agent") if _unit_installed(node, u)]
    if rke2_paths or rke2_units:
        signals.extend(f"path:{p}" for p in rke2_paths)
        signals.extend(f"unit:{u}" for u in rke2_units)
        server = _dir(node, "/var/lib/rancher/rke2/server") or _unit_installed(
            node, "rke2-server"
        )
        return DistroInfo(
            family="rke2",
            role="server" if server else "agent",
            signals=signals,
            server_units=["rke2-server"] if server else [],
            agent_units=["rke2-agent"] if not server else ["rke2-server"],
            config_paths=["/etc/rancher/rke2/config.yaml"],
            data_dirs=["/var/lib/rancher/rke2"],
            notes=(
                "RKE2 supervises the control plane from the rke2-server unit and writes static "
                "pod manifests under /var/lib/rancher/rke2/agent/pod-manifests."
            ),
        )

    # --- microk8s ----------------------------------------------------------------------
    if _dir(node, "/var/snap/microk8s"):
        signals.append("path:/var/snap/microk8s")
        units = [
            u
            for u in (
                "snap.microk8s.daemon-kubelite",
                "snap.microk8s.daemon-k8s-dqlite",
                "snap.microk8s.daemon-containerd",
                "snap.microk8s.daemon-kubelet",
            )
            if _unit_installed(node, u)
        ]
        signals.extend(f"unit:{u}" for u in units)
        control_plane = _file(node, "/var/snap/microk8s/current/args/kube-apiserver")
        return DistroInfo(
            family="microk8s",
            role="control-plane" if control_plane else "worker",
            signals=signals,
            server_units=[u for u in units if "kubelite" in u] or ["snap.microk8s.daemon-kubelite"],
            agent_units=[u for u in units if "kubelet" in u]
            or ["snap.microk8s.daemon-kubelite"],
            config_paths=[
                "/var/snap/microk8s/current/args/kube-apiserver",
                "/var/snap/microk8s/current/args/kubelet",
            ],
            data_dirs=["/var/snap/microk8s/current"],
            notes=(
                "microk8s runs the control plane as the kubelite snap daemon and keeps "
                "component flags as argument files under /var/snap/microk8s/current/args."
            ),
        )

    # --- kubeadm and other static-pod layouts -------------------------------------------
    manifests = [
        name
        for name in ("kube-apiserver.yaml", "kube-scheduler.yaml", "etcd.yaml")
        if _file(node, f"/etc/kubernetes/manifests/{name}")
    ]
    kubelet_unit = _unit_installed(node, "kubelet")
    if manifests or _dir(node, "/etc/kubernetes/manifests") or kubelet_unit:
        signals.extend(f"manifest:{m}" for m in manifests)
        if kubelet_unit:
            signals.append("unit:kubelet")
        if _file(node, "/etc/kubernetes/admin.conf"):
            signals.append("path:/etc/kubernetes/admin.conf")
        return DistroInfo(
            family="kubeadm",
            role="control-plane" if manifests else "worker",
            signals=signals,
            server_units=["kube-apiserver", "kube-controller-manager", "kube-scheduler"]
            if manifests
            else [],
            agent_units=["kubelet"],
            config_paths=["/etc/kubernetes/manifests/kube-apiserver.yaml"],
            data_dirs=["/var/lib/etcd", "/etc/kubernetes"],
            notes=(
                "kubeadm-style layout: control-plane components run as static pods with their "
                "own log trees under /var/log/pods."
            ),
        )

    # --- unknown (managed worker, or a layout we have not seen) --------------------------
    return DistroInfo(
        family="unknown",
        role="worker" if _dir(node, "/var/log/pods") else "unknown",
        signals=signals,
        server_units=[],
        agent_units=["kubelet"],
        config_paths=[],
        data_dirs=[],
        notes=(
            "No known distribution layout found. This is normal on a managed worker "
            "(EKS / GKE / AKS), where the control plane is not on this node at all. "
            "Collectors fall back to their default paths and record what they tried."
        ),
    )


# -- per-concern helpers --------------------------------------------------------------------


def control_plane_units(info: DistroInfo) -> list[str]:
    """Units to read for control-plane logs, best first."""
    if info.merged_control_plane:
        return list(info.server_units)
    return []


def node_agent_units(info: DistroInfo) -> list[str]:
    """Units to read for kubelet logs after the plain ``kubelet`` unit, best first."""
    out: list[str] = []
    for unit in info.agent_units:
        if unit != "kubelet" and unit not in out:
            out.append(unit)
    return out


def apiserver_flag_sources(info: DistroInfo) -> list[str]:
    """Files that may carry ``--audit-log-path`` and friends, in resolution order.

    The kubeadm static pod manifest first (it is the most explicit), then the distro's own
    config, then the unit file whose ``ExecStart`` line carries the flags.
    """
    out = ["/etc/kubernetes/manifests/kube-apiserver.yaml"]
    if info.family == "rke2":
        out.append("/var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml")
    out.extend(p for p in info.config_paths if p not in out)
    for unit in info.server_units:
        name = unit if unit.endswith(".service") else f"{unit}.service"
        for directory in _UNIT_DIRS:
            path = f"{directory}/{name}"
            if path not in out:
                out.append(path)
    return out


def datastore_paths(info: DistroInfo) -> list[dict[str, str]]:
    """Where this distro keeps cluster state, and what kind of store it is.

    ``kind`` is ``etcd``, ``sqlite`` or ``dqlite``. The distinction matters: a sqlite or
    dqlite datastore has no client-certificate model at all, so "is client cert auth on" is
    the wrong question and file permissions are the whole control.
    """
    if info.family == "k3s":
        return [
            {"kind": "etcd", "path": "/var/lib/rancher/k3s/server/db/etcd"},
            {"kind": "sqlite", "path": "/var/lib/rancher/k3s/server/db/state.db"},
        ]
    if info.family == "rke2":
        return [{"kind": "etcd", "path": "/var/lib/rancher/rke2/server/db/etcd"}]
    if info.family == "microk8s":
        return [
            {"kind": "dqlite", "path": "/var/snap/microk8s/current/var/kubernetes/backend"}
        ]
    return [{"kind": "etcd", "path": "/var/lib/etcd"}]


def datastore_tls_dirs(info: DistroInfo) -> list[str]:
    """Directories holding the datastore's TLS material, if the distro uses any."""
    if info.family == "k3s":
        return ["/var/lib/rancher/k3s/server/tls/etcd"]
    if info.family == "rke2":
        return ["/var/lib/rancher/rke2/server/tls/etcd"]
    if info.family == "microk8s":
        return []
    return ["/etc/kubernetes/pki/etcd"]
