"""k8s_checkpoint — live container memory capture via CRIU (on-prem exclusive).

POSTs to the kubelet checkpoint endpoint on the target node:

    POST https://localhost:10250/checkpoint/<namespace>/<pod>/<container>

The kubelet asks the CRI runtime, which invokes CRIU, which dumps the container's full process
memory *without stopping it and without the container being aware*. The archive lands at
``/var/lib/kubelet/checkpoints/checkpoint-<pod>_<ns>-<container>-<ts>.tar``.

Guards (non-negotiable):
  * **Capability probe first.** The endpoint returns HTTP 500 when the runtime doesn't
    implement checkpointing, or for GPU/InfiniBand containers (no CRIU plugin). We probe and
    emit NOT_SUPPORTED rather than failing the run.
  * **Treat the archive as a secret.** It contains every memory page of every process —
    plaintext credentials, private keys, session tokens. It is marked maximum-sensitivity in
    the manifest; encryption at rest and access gating happen at the storage layer.
  * Never restore a checkpoint into the production cluster (this collector only captures).
"""

from __future__ import annotations

from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile
from collector.lib.params import param_strings

from ..common.nodebase import NodePlaneCollector

_KUBELET_ENDPOINT = "https://localhost:10250"
_CHECKPOINT_DIR = "/var/lib/kubelet/checkpoints"
# The archive is maximum sensitivity — surfaced in config so the storage layer can gate it.
_SENSITIVITY = "maximum"


class CheckpointCollector(NodePlaneCollector):
    name = "k8s_checkpoint"
    priority = 3
    description = "Live container memory capture via kubelet CRIU checkpoint (max sensitivity)."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        gaps: list[tuple[str, GapReason, str]] = []
        nc = self.node_context()

        targets = self._targets()
        if not targets:
            return SourceResult(
                name=self.name,
                status=SourceStatus.SKIPPED,
                gaps=[
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        "No checkpoint targets. Provide 'targets' as namespace/pod/container "
                        "triples (this is a deliberate, high-impact capture — never run blanket).",
                    )
                ],
                notes="No checkpoint targets specified.",
            )

        if not self._capability_probe(node, gaps):
            return SourceResult(
                name=self.name,
                status=SourceStatus.SKIPPED,
                gaps=gaps,
                notes="Container checkpointing not supported on this node/runtime.",
            )

        files: list[WrittenFile] = []
        manifest: list[dict[str, Any]] = []
        captured = 0
        for target in targets:
            ns, pod, container = target
            wf, reason = self._checkpoint_one(node, ns, pod, container)
            if wf is None:
                gaps.append((self.name, reason[0], reason[1]))
                continue
            captured += 1
            files.append(wf)
            manifest.append(
                {
                    "namespace": ns,
                    "pod": pod,
                    "container": container,
                    "archive_path": wf.path,
                    "sha256": wf.sha256,
                    "bytes": wf.bytes,
                    "sensitivity": _SENSITIVITY,
                }
            )

        files.append(
            self.write_json(
                {
                    "targets": [f"{n}/{p}/{c}" for n, p, c in targets],
                    "captured": captured,
                    "sensitivity": _SENSITIVITY,
                    "node": nc.to_dict(),
                    "manifest": manifest,
                    "warning": "Checkpoint archives contain full process memory (credentials, "
                    "keys, tokens). Maximum sensitivity: encrypt at rest, gate access, log reads.",
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "captured": captured, "sensitivity": _SENSITIVITY})

        if captured == 0:
            status = SourceStatus.SKIPPED if gaps else SourceStatus.EMPTY
        else:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=captured,
            gaps=gaps,
            notes=f"{captured}/{len(targets)} checkpoint(s) captured (max sensitivity).",
        )

    def _targets(self) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        for raw in param_strings(self.artifact_params(), "targets"):
            parts = raw.split("/")
            if len(parts) == 3 and all(parts):
                out.append((parts[0], parts[1], parts[2]))
        return out

    def _capability_probe(self, node: Any, gaps: list) -> bool:
        """Probe support before attempting a real checkpoint.

        CRI-O needs ``enable_criu_support = true``; the ``ContainerCheckpoint`` feature gate is
        beta/enabled-by-default since k8s v1.30 but pre-GA. An unsupported runtime returns
        HTTP 500 — we degrade to NOT_SUPPORTED instead of failing the run.
        """
        runtime = node.runtime_info()
        if runtime.runtime == "docker":
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_SUPPORTED,
                    "Docker runtime does not support the CRI checkpoint API.",
                )
            )
            return False
        if not node.have("curl") and not _has_requests():
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_SUPPORTED,
                    "No HTTP client (curl/requests) available on node to reach the kubelet "
                    "checkpoint endpoint.",
                )
            )
            return False
        # A cheap probe: the endpoint requires POST; a GET/OPTIONS-style 404/405 means the route
        # exists (supported), a connection failure or 500 for a probe container means unsupported.
        status = self._probe_status(node)
        if status in (401, 404, 405, 200):
            return True
        gaps.append(
            (
                self.name,
                GapReason.NOT_SUPPORTED,
                f"kubelet checkpoint endpoint probe returned {status}; container checkpointing "
                "is not available (runtime lacks CRIU support, or feature gate disabled).",
            )
        )
        return False

    def _probe_status(self, node: Any) -> int:
        # POST to a non-existent container: a supported kubelet returns 404 (route present);
        # an unsupported one returns 500 or the connection is refused.
        url = f"{_KUBELET_ENDPOINT}/checkpoint/ventra-probe/ventra-probe/ventra-probe"
        rc, out, _ = node.run(
            [
                "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                "-X", "POST", "--max-time", "10",
                "--cacert", "/var/lib/kubelet/pki/kubelet.crt",
                url,
            ]
        )
        if rc == 0 and out.strip().isdigit():
            return int(out.strip())
        # Retry without cert pinning (self-signed kubelet certs are common).
        rc, out, _ = node.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
             "--max-time", "10", url]
        )
        if rc == 0 and out.strip().isdigit():
            return int(out.strip())
        return -1

    def _checkpoint_one(
        self, node: Any, ns: str, pod: str, container: str
    ) -> tuple[WrittenFile | None, tuple[GapReason, str]]:
        url = f"{_KUBELET_ENDPOINT}/checkpoint/{ns}/{pod}/{container}"
        rc, out, err = node.run(
            ["curl", "-sk", "-w", "\\n%{http_code}", "-X", "POST", "--max-time", "120", url],
            timeout=180,
        )
        if rc != 0:
            return None, (GapReason.COLLECTOR_ERROR, f"{ns}/{pod}/{container}: curl failed: {err.strip()}")
        body, _, code = out.rpartition("\n")
        if code.strip() == "500":
            return None, (
                GapReason.NOT_SUPPORTED,
                f"{ns}/{pod}/{container}: kubelet returned 500 — runtime cannot checkpoint this "
                "container (GPU/InfiniBand, or no CRIU plugin).",
            )
        if code.strip() not in ("200", "201"):
            return None, (
                GapReason.COLLECTOR_ERROR,
                f"{ns}/{pod}/{container}: kubelet returned {code.strip()}: {body[:200]}",
            )
        archive = self._find_checkpoint_archive(node, ns, pod, container)
        if archive is None:
            return None, (
                GapReason.NOT_PRESENT,
                f"{ns}/{pod}/{container}: checkpoint reported success but no archive found in "
                f"{_CHECKPOINT_DIR}.",
            )
        wf = self.copy_node_file(archive, f"checkpoints/{archive.split('/')[-1]}")
        if wf is None:
            return None, (GapReason.COLLECTOR_ERROR, f"{ns}/{pod}/{container}: archive unreadable.")
        return wf, (GapReason.NOT_PRESENT, "")

    def _find_checkpoint_archive(self, node: Any, ns: str, pod: str, container: str) -> str | None:
        # checkpoint-<pod>_<ns>-<container>-<timestamp>.tar
        matches = node.iter_glob(f"{_CHECKPOINT_DIR}/checkpoint-{pod}_{ns}-{container}-*.tar")
        if not matches:
            matches = node.iter_glob(f"{_CHECKPOINT_DIR}/*{pod}*{container}*.tar")
        if not matches:
            return None
        newest = max(matches, key=lambda p: p.stat().st_mtime if p.exists() else 0)
        return "/" + newest.relative_to(node.root).as_posix()


def _has_requests() -> bool:
    try:
        import requests  # noqa: F401,PLC0415
    except ImportError:
        return False
    return True
