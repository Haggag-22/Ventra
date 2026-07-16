"""k8s_etcd — etcd logs and TLS/config posture (on-prem exclusive).

Collects etcd logs and — importantly — its security posture: is client cert auth enforced, is
it listening on a non-loopback address, is it unencrypted at rest? It does **not** dump the
etcd database by default: that database contains every Secret in the cluster in plaintext
(unless encryption-at-rest is on). A database dump is an explicit, separately-confirmed
parameter and the resulting artifact is treated as maximum-sensitivity.
"""

from __future__ import annotations

import re
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile
from collector.lib.params import param_bool

from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector

_ETCD_MANIFEST = "/etc/kubernetes/manifests/etcd.yaml"
_ETCD_LOG_GLOB = "/var/log/pods/kube-system_etcd-*/*/*.log"


class EtcdCollector(NodePlaneCollector):
    name = "k8s_etcd"
    priority = 2
    description = "etcd logs + TLS/at-rest posture (never dumps the DB by default; on-prem)."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        gaps: list[tuple[str, GapReason, str]] = []
        files = []

        posture = self._posture(node)
        for issue in posture.get("issues", []):
            gaps.append((self.name, GapReason.LOGGING_NOT_CONFIGURED, issue))

        # Logs: static pod first, journal fallback.
        records: list[dict[str, Any]] = []
        for path in node.iter_glob(_ETCD_LOG_GLOB):
            host_path = "/" + path.relative_to(node.root).as_posix()
            wf = self.copy_node_file(host_path, f"logs/{path.name}")
            if wf is not None:
                files.append(wf)
        if not files:
            journal = collect_unit(node, "etcd", fallback_files=("/var/log/etcd.log",))
            records = journal["records"]
            for rec in records:
                nc.stamp(rec)
            if records:
                files.append(self.write_jsonl(records, "etcd.jsonl.gz"))

        db_dumped = False
        self._snapshot_file: WrittenFile | None = None
        if param_bool(self.artifact_params(), "dump_db"):
            db_dumped = self._maybe_dump_db(node, gaps)
            if self._snapshot_file is not None:
                files.append(self._snapshot_file)

        files.append(
            self.write_json(
                {"posture": posture, "db_dumped": db_dumped, "node": nc.to_dict()}, "config.json"
            )
        )
        self.write_meta({"source": self.name, "posture_issues": len(posture.get("issues", []))})

        collected = len(files) > 1 or bool(records)
        status = SourceStatus.PARTIAL if gaps and collected else (
            SourceStatus.COLLECTED if collected else SourceStatus.EMPTY
        )
        if not collected and not gaps:
            gaps.append((self.name, GapReason.NOT_PRESENT, "No etcd logs or manifest on this node."))
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"etcd posture: {len(posture.get('issues', []))} issue(s); db_dumped={db_dumped}.",
        )

    def _posture(self, node: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"determined": False, "issues": [], "flags": {}}
        if not node.exists(_ETCD_MANIFEST):
            out["issues"].append("etcd static pod manifest not found — posture undetermined.")
            return out
        try:
            text = node.read_text(_ETCD_MANIFEST)
        except Exception as exc:  # noqa: BLE001
            out["issues"].append(f"could not read etcd manifest: {exc}")
            return out
        out["determined"] = True
        flags = {}
        for flag in (
            "client-cert-auth",
            "peer-client-cert-auth",
            "listen-client-urls",
            "cert-file",
            "trusted-ca-file",
        ):
            m = re.search(rf"--{re.escape(flag)}[= ]([^\s\"']+)", text)
            if m:
                flags[flag] = m.group(1)
        out["flags"] = flags

        if flags.get("client-cert-auth", "").lower() != "true":
            out["issues"].append(
                "etcd client certificate auth is NOT enforced (--client-cert-auth != true). "
                "Any client that can reach etcd has full cluster control."
            )
        listen = flags.get("listen-client-urls", "")
        if listen and not all(_is_loopback(u) for u in listen.split(",")):
            out["issues"].append(
                f"etcd is listening on a non-loopback address ({listen}). Direct etcd access "
                "from anything other than the API server is total cluster compromise."
            )
        return out

    def _maybe_dump_db(self, node: Any, gaps: list) -> bool:
        """Explicit, separately-confirmed etcd snapshot. Maximum sensitivity.

        ``etcdctl snapshot save`` must write the DB somewhere. We point it straight at the
        collector's own staging dir (never a host path — the host mount is read-only, and
        writing to the node would be a side effect), then hash the resulting file in place.
        """
        from collector.lib.chain_of_custody.hashing import sha256_file

        dest = self.ctx.source_dir(self.name) / "etcd-snapshot.db"
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, _out, err = node.run(
            ["etcdctl", "snapshot", "save", str(dest)], timeout=300
        )
        if rc != 0 or not dest.exists():
            gaps.append((self.name, GapReason.NOT_SUPPORTED, f"etcd snapshot failed: {err.strip()}"))
            return False
        self._snapshot_file = WrittenFile(
            path=dest.relative_to(self.ctx.staging).as_posix(),
            sha256=sha256_file(dest),
            bytes=dest.stat().st_size,
        )
        return True


def _is_loopback(url: str) -> bool:
    url = url.strip().lower()
    return "127.0.0.1" in url or "localhost" in url or "[::1]" in url
