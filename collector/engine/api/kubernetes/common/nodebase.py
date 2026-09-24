"""Shared base for node-plane collectors.

Node-plane collectors read the node filesystem/journal/CRI socket via ``ctx.client_factory``
(a :class:`KubernetesClientFactory` whose ``node`` attribute is a :class:`NodeAccess`). This
base resolves the per-run :class:`NodeContext` once and exposes it, plus a helper that copies
a node file into the collector's staging dir, hashing it on acquisition.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from collector.lib.base import Collector
from collector.lib.models import WrittenFile

from .distro import DistroInfo, detect_distro
from .nodecontext import NodeContext, build_node_context

_CHUNK = 1024 * 1024


class NodePlaneCollector(Collector):
    """Base class for collectors that read the node directly (no API-server calls)."""

    plane = "node"

    @property
    def node(self) -> Any:
        """The :class:`NodeAccess` for this run."""
        return self.ctx.client_factory.node

    def distro(self) -> DistroInfo:
        """The Kubernetes distribution this node runs (kubeadm, k3s, RKE2, microk8s, …).

        Resolved once per run and shared by every node-plane collector, so each one can pick
        the right paths and units instead of assuming a kubeadm layout.
        """
        return detect_distro(self.node)

    def node_context(self) -> NodeContext:
        nc = getattr(self, "_node_context", None)
        if nc is None:
            cluster_id = getattr(self.ctx, "account_id", "") or ""
            nc = build_node_context(self.node, cluster_id=cluster_id)
            self._node_context = nc
        return nc

    # -- evidence capture (streaming + hashed on acquisition) -----------------------------

    def capture_path(self, src: Path, dest_rel: str, *, max_bytes: int | None = None) -> WrittenFile | None:
        """Copy a resolved node ``Path`` into staging, hashing it in a single streamed pass.

        Streams in chunks so a multi-GB log never has to fit in memory, and computes the
        SHA-256 over the same bytes it writes (no second read). Returns ``None`` for anything
        that is not a regular file, a symlink (never followed — evidence must not escape the
        captured tree), or a file larger than ``max_bytes``.
        """
        try:
            if src.is_symlink() or not src.is_file():
                return None
            if max_bytes is not None and src.stat().st_size > max_bytes:
                return None
        except OSError:
            return None
        out_path = self.ctx.source_dir(self.name) / dest_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256()
        total = 0
        try:
            with src.open("rb") as fin, out_path.open("wb") as fout:
                for chunk in iter(lambda: fin.read(_CHUNK), b""):
                    fout.write(chunk)
                    h.update(chunk)
                    total += len(chunk)
        except OSError:
            out_path.unlink(missing_ok=True)
            return None
        return WrittenFile(
            path=out_path.relative_to(self.ctx.staging).as_posix(),
            sha256=h.hexdigest(),
            bytes=total,
        )

    def capture_file(
        self, host_path: str, dest_rel: str, *, max_bytes: int | None = None
    ) -> WrittenFile | None:
        """Capture a host-absolute node path (``/var/log/...``) into staging. See :meth:`capture_path`."""
        return self.capture_path(self.node.resolve(host_path), dest_rel, max_bytes=max_bytes)

    # Back-compat alias: several collectors and tests call ``copy_node_file(host_path, name)``.
    copy_node_file = capture_file

    def write_node_bytes(self, data: bytes, dest_name: str) -> WrittenFile:
        """Write captured bytes (command output, exported tar) into staging with a hash."""
        out_path = self.ctx.source_dir(self.name) / dest_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        return WrittenFile(
            path=out_path.relative_to(self.ctx.staging).as_posix(),
            sha256=hashlib.sha256(data).hexdigest(),
            bytes=len(data),
        )

    @staticmethod
    def _dest_from_host_path(host_path: str) -> str:
        return Path(host_path).name
