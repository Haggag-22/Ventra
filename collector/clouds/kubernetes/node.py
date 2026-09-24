"""Node-plane filesystem, journal, and container-runtime access for on-prem Kubernetes.

A node-plane collector never talks to the Kubernetes API server. It reads the node's own
filesystem, the systemd journal, and the CRI socket directly. In production that filesystem
is the host root mounted **read-only** into the collector DaemonSet/Job pod at ``root``
(commonly ``/host``); in tests ``root`` is a temporary directory laid out the same way.

Nothing in this module writes to the node. Every path read is resolved under ``root`` so a
collector can never escape the mount, and every external command is wrapped so a missing
binary degrades to a recorded gap instead of crashing the run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Runtime CRI sockets, in detection priority order. Dockershim was removed in Kubernetes
# v1.24, so Docker is only ever reported for ancient clusters and behind a legacy flag.
#
# k3s, RKE2 and microk8s all embed containerd and put its socket somewhere of their own, so
# those paths are probed alongside the standard one. Without them a k3s node looks like it
# has no container runtime at all.
_CONTAINERD_SOCKETS = (
    "run/containerd/containerd.sock",
    "run/k3s/containerd/containerd.sock",  # k3s and RKE2
    "var/snap/microk8s/common/run/containerd.sock",  # microk8s
)
_CRIO_SOCKETS = ("var/run/crio/crio.sock", "run/crio/crio.sock")
_DOCKER_SOCKETS = ("var/run/docker.sock", "run/docker.sock")

# Storage roots, probed when no socket is mounted into the collector pod.
_CONTAINERD_STORAGE = "var/lib/containerd"
_CONTAINERD_STORAGE_ALTS = (
    "var/lib/containerd",
    "var/lib/rancher/k3s/agent/containerd",
    "var/lib/rancher/rke2/agent/containerd",
    "var/snap/microk8s/common/var/lib/containerd",
)
_CRIO_STORAGE = "var/lib/containers"
_DOCKER_STORAGE = "var/lib/docker"


@dataclass
class RuntimeInfo:
    """The container runtime detected on the node — resolved once, up front."""

    runtime: str = "unknown"  # containerd | cri-o | docker | unknown
    version: str = ""
    socket: str = ""  # host-absolute CRI socket path (as the kubelet sees it)
    storage_root: str = ""  # host-absolute overlay/storage root
    detected_from: str = ""  # socket | storage | none

    def to_dict(self) -> dict[str, object]:
        return {
            "runtime": self.runtime,
            "version": self.version,
            "socket": self.socket,
            "storage_root": self.storage_root,
            "detected_from": self.detected_from,
        }


@dataclass
class NodeAccess:
    """Read-only accessor for the node filesystem and its container runtime.

    ``root`` is where the host filesystem is mounted (``/`` when running directly on the
    node, ``/host`` inside a DaemonSet). ``crictl`` / ``journalctl`` are optional: when the
    binary is absent :meth:`run` returns a non-zero result and the caller records a gap.
    """

    root: Path = field(default_factory=lambda: Path("/"))
    node_name: str = ""
    command_timeout: int = 120
    _runtime: RuntimeInfo | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        if not self.node_name:
            self.node_name = os.environ.get("VENTRA_NODE_NAME", "") or ""

    # -- path resolution (never escapes ``root``) ----------------------------------------

    def resolve(self, host_path: str) -> Path:
        """Map a host-absolute path (``/var/log/...``) to its location under ``root``."""
        rel = str(host_path).lstrip("/")
        return self.root / rel

    def exists(self, host_path: str) -> bool:
        return self.resolve(host_path).exists()

    def is_dir(self, host_path: str) -> bool:
        return self.resolve(host_path).is_dir()

    def read_bytes(self, host_path: str) -> bytes:
        return self.resolve(host_path).read_bytes()

    def read_text(self, host_path: str, *, errors: str = "replace") -> str:
        return self.resolve(host_path).read_text(encoding="utf-8", errors=errors)

    def iter_glob(self, host_glob: str) -> list[Path]:
        """Glob a host-absolute pattern under ``root``; returns sorted absolute paths."""
        rel = str(host_glob).lstrip("/")
        return sorted(self.root.glob(rel))

    # -- external commands (crictl / journalctl / kubelet) --------------------------------

    def have(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    def run(self, args: list[str], *, timeout: int | None = None) -> tuple[int, str, str]:
        """Run a read-only node command. Missing binary → ``(-1, "", reason)`` (never raises)."""
        if not args or not self.have(args[0]):
            return -1, "", f"{args[0] if args else 'command'}: not available on node"
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout or self.command_timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:  # pragma: no cover - env dependent
            return -1, "", str(exc)
        return proc.returncode, proc.stdout, proc.stderr

    def crictl(self, *args: str) -> list[str]:
        """``crictl`` argv pointed at the CRI socket this node actually uses.

        The socket is not in the same place on every distribution (k3s and RKE2 use
        ``/run/k3s/containerd/containerd.sock``, microk8s its own snap path), and when the
        host is mounted at ``root`` the socket is only reachable through that mount. Passing
        ``--runtime-endpoint`` explicitly means crictl works in both cases instead of relying
        on its built-in path list matching the layout we are standing on.
        """
        info = self.runtime_info()
        argv = ["crictl"]
        if info.socket:
            endpoint = self.resolve(info.socket)
            argv.extend(["--runtime-endpoint", f"unix://{endpoint}"])
        argv.extend(args)
        return argv

    # -- runtime detection (mandatory, up front) ------------------------------------------

    def runtime_info(self) -> RuntimeInfo:
        if self._runtime is None:
            self._runtime = self._detect_runtime()
        return self._runtime

    def _detect_runtime(self) -> RuntimeInfo:
        for sockets, name, storages in (
            (_CONTAINERD_SOCKETS, "containerd", _CONTAINERD_STORAGE_ALTS),
            (_CRIO_SOCKETS, "cri-o", (_CRIO_STORAGE,)),
            (_DOCKER_SOCKETS, "docker", (_DOCKER_STORAGE,)),
        ):
            for sock in sockets:
                if self.resolve(sock).exists():
                    storage = next((s for s in storages if self.resolve(s).is_dir()), storages[0])
                    return RuntimeInfo(
                        runtime=name,
                        version=self._runtime_version(),
                        socket="/" + sock,
                        storage_root="/" + storage,
                        detected_from="socket",
                    )
        # No socket mounted (common in tests / restricted mounts): fall back to storage dirs.
        for storage, name in (
            *((s, "containerd") for s in _CONTAINERD_STORAGE_ALTS),
            (_CRIO_STORAGE, "cri-o"),
            (_DOCKER_STORAGE, "docker"),
        ):
            if self.resolve(storage).is_dir():
                return RuntimeInfo(
                    runtime=name,
                    version=self._runtime_version(),
                    storage_root="/" + storage,
                    detected_from="storage",
                )
        return RuntimeInfo(runtime="unknown", detected_from="none")

    def _runtime_version(self) -> str:
        # Deliberately not self.crictl(): runtime_info() is still being resolved here.
        rc, out, _ = self.run(["crictl", "version"])
        if rc != 0:
            return ""
        for line in out.splitlines():
            if line.upper().startswith("RUNTIMEVERSION"):
                return line.split(":", 1)[-1].strip()
        return out.strip().splitlines()[0] if out.strip() else ""

    # -- host facts for NodeContext -------------------------------------------------------

    def kernel(self) -> str:
        version_file = self.resolve("proc/version")
        if version_file.exists():
            try:
                return version_file.read_text(errors="replace").split()[2]
            except (IndexError, OSError):
                pass
        rc, out, _ = self.run(["uname", "-r"])
        return out.strip() if rc == 0 else ""

    def hostname(self) -> str:
        if self.node_name:
            return self.node_name
        host_file = self.resolve("etc/hostname")
        if host_file.exists():
            try:
                return host_file.read_text(errors="replace").strip()
            except OSError:
                pass
        return ""

    def kubelet_version(self) -> str:
        rc, out, _ = self.run(["kubelet", "--version"])
        if rc == 0 and out.strip():
            return out.strip().split()[-1]
        return ""
