"""k8s_container_fs — container filesystem changes (dropped binaries, webshells, miners).

For each *implicated* container this captures the OverlayFS upper (read-write) layer — every
file the container created or modified since it started from its image — plus in-container
shell history. The overlay path is resolved at runtime via ``crictl inspect`` (containerd and
CRI-O lay storage out differently, so paths are never hardcoded). Every extracted file is
hashed (sha256) at acquisition time.

This is priority 1 because ``--rm``-equivalent semantics and evicted/restarted pods lose all
of this on exit. It targets only the containers implicated in the incident — never a full
export of every container in the cluster.
"""

from __future__ import annotations

import json
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile
from collector.lib.params import param_bool, param_strings

from ..common.nodebase import NodePlaneCollector

_SHELL_HISTORIES = (
    "root/.bash_history",
    "root/.ash_history",
    "root/.zsh_history",
    "root/.sh_history",
)
_MAX_FILE_BYTES = 64 * 1024 * 1024  # skip absurdly large single files in the upper layer


class ContainerFsCollector(NodePlaneCollector):
    name = "k8s_container_fs"
    priority = 1
    description = "OverlayFS upper layer + shell history for implicated containers (on-prem)."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        gaps: list[tuple[str, GapReason, str]] = []
        nc = self.node_context()
        runtime = node.runtime_info()

        if runtime.runtime == "docker" and not param_bool(self.artifact_params(), "allow_docker"):
            return SourceResult(
                name=self.name,
                status=SourceStatus.SKIPPED,
                gaps=[
                    (
                        self.name,
                        GapReason.NOT_SUPPORTED,
                        "Docker runtime detected (dockershim removed in k8s v1.24). Container-fs "
                        "collection via crictl is CRI-only; set allow_docker to force a legacy path.",
                    )
                ],
                notes="Docker runtime — skipped (use crictl on a CRI runtime).",
            )

        targets = self._resolve_targets(node, gaps)
        if not targets:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        "No implicated containers resolved. Provide container_ids / pods / "
                        "namespaces, or run where crictl can enumerate containers.",
                    )
                ],
                notes="No target containers.",
            )

        files: list[WrittenFile] = []
        manifest: list[dict[str, Any]] = []
        extracted = 0
        want_export = param_bool(self.artifact_params(), "full_export")

        for target in targets:
            upperdir = target.get("upperdir", "")
            cid = target.get("id", "")
            if not upperdir or not node.is_dir(upperdir):
                gaps.append(
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        f"container {cid or '?'}: overlay upperdir '{upperdir}' not readable.",
                    )
                )
                continue
            container_files, container_manifest = self._capture_upper(node, cid, upperdir, target)
            files.extend(container_files)
            manifest.extend(container_manifest)
            extracted += len(container_files)
            if want_export:
                wf = self._export_tar(node, cid, upperdir)
                if wf is not None:
                    files.append(wf)
                    manifest.append(
                        {
                            "container": cid,
                            "kind": "full_export",
                            "archive_path": wf.path,
                            "sha256": wf.sha256,
                        }
                    )

        files.append(
            self.write_json(
                {
                    "runtime": runtime.to_dict(),
                    "targets": targets,
                    "extracted_files": extracted,
                    "node": nc.to_dict(),
                    "manifest": manifest,
                },
                "config.json",
            )
        )
        self.write_meta({"source": self.name, "extracted_files": extracted})

        status = SourceStatus.PARTIAL if (gaps and extracted) else (
            SourceStatus.COLLECTED if extracted else SourceStatus.EMPTY
        )
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=extracted,
            gaps=gaps,
            notes=f"{extracted} file(s) from {len(targets)} implicated container(s).",
        )

    def _resolve_targets(self, node: Any, gaps: list) -> list[dict[str, Any]]:
        """Resolve implicated containers to {id, upperdir, name, pod, namespace}.

        Explicit ``container_upperdirs`` params win (used in constrained mounts and tests);
        otherwise ``crictl inspect`` resolves the overlay path per container id.
        """
        params = self.artifact_params()
        targets: list[dict[str, Any]] = []

        explicit_dirs = param_strings(params, "container_upperdirs")
        for i, d in enumerate(explicit_dirs):
            targets.append({"id": f"explicit-{i}", "upperdir": d})

        cids = param_strings(params, "container_ids")
        if not cids and not explicit_dirs:
            cids = self._crictl_container_ids(node, params, gaps)
        for cid in cids:
            info = self._crictl_upperdir(node, cid)
            if info:
                targets.append(info)
            else:
                gaps.append(
                    (self.name, GapReason.NOT_PRESENT, f"could not resolve overlay for {cid}.")
                )
        return targets

    def _crictl_container_ids(self, node: Any, params: dict, gaps: list) -> list[str]:
        rc, out, err = node.run(["crictl", "ps", "-a", "-o", "json"])
        if rc != 0:
            gaps.append((self.name, GapReason.NOT_PRESENT, f"crictl ps unavailable: {err.strip()}"))
            return []
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return []
        ns_filter = [n.lower() for n in param_strings(params, "namespaces")]
        pod_filter = [p.lower() for p in param_strings(params, "pods")]
        ids: list[str] = []
        for c in data.get("containers") or []:
            labels = c.get("labels") or {}
            ns = str(labels.get("io.kubernetes.pod.namespace", "")).lower()
            pod = str(labels.get("io.kubernetes.pod.name", "")).lower()
            if ns_filter and ns not in ns_filter:
                continue
            if pod_filter and pod not in pod_filter:
                continue
            if c.get("id"):
                ids.append(c["id"])
        return ids

    def _crictl_upperdir(self, node: Any, cid: str) -> dict[str, Any] | None:
        rc, out, _ = node.run(["crictl", "inspect", cid])
        if rc != 0:
            return None
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return None
        upperdir = _find_upperdir(data)
        if not upperdir:
            return None
        status = data.get("status") or {}
        meta = status.get("metadata") or {}
        labels = status.get("labels") or {}
        return {
            "id": cid,
            "upperdir": upperdir,
            "name": meta.get("name", ""),
            "pod": labels.get("io.kubernetes.pod.name", ""),
            "namespace": labels.get("io.kubernetes.pod.namespace", ""),
        }

    def _capture_upper(
        self, node: Any, cid: str, upperdir: str, target: dict[str, Any]
    ) -> tuple[list[WrittenFile], list[dict[str, Any]]]:
        files: list[WrittenFile] = []
        manifest: list[dict[str, Any]] = []
        base = node.resolve(upperdir)
        for path in sorted(base.rglob("*")):
            # Skip symlinks (never follow them out of the captured layer), directories, and
            # device/whiteout nodes; only regular files under the size cap are evidence.
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(base).as_posix()
            wf = self.capture_path(
                path, f"changed/{_safe_cid(cid)}/{rel}", max_bytes=_MAX_FILE_BYTES
            )
            if wf is None:
                continue
            files.append(wf)
            manifest.append(
                {
                    "container": cid,
                    "kind": "shell_history" if _is_shell_history(rel) else "changed_file",
                    "container_path": "/" + rel,
                    "archive_path": wf.path,
                    "sha256": wf.sha256,
                    "bytes": wf.bytes,
                }
            )
        return files, manifest

    def _export_tar(self, node: Any, cid: str, upperdir: str) -> WrittenFile | None:
        """Full changed-layer tar for the most-implicated containers (opt-in)."""
        import io
        import tarfile

        base = node.resolve(upperdir)
        if not base.is_dir():
            return None
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(str(base), arcname=_safe_cid(cid), recursive=True)
        return self.write_node_bytes(buf.getvalue(), f"export-{_safe_cid(cid)}.tar.gz")


def _find_upperdir(inspect: dict[str, Any]) -> str:
    """Locate the overlay upperdir in a crictl inspect blob, runtime-agnostically."""
    # Common shapes: status.info.runtimeSpec.linux; info.runtimeSpec; GraphDriver.Data.UpperDir.
    def _walk(obj: Any) -> str:
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key in ("UpperDir", "upperdir") and isinstance(val, str):
                    return val
                if key == "upperDir" and isinstance(val, str):
                    return val
                found = _walk(val)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = _walk(item)
                if found:
                    return found
        elif isinstance(obj, str) and "/diff" in obj and "overlay" in obj:
            return obj
        return ""

    return _walk(inspect)


def _is_shell_history(rel: str) -> bool:
    return any(rel.endswith(h.split("/")[-1]) for h in _SHELL_HISTORIES)


def _safe_cid(cid: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in cid)[:64] or "container"
