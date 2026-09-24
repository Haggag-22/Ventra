"""k8s_etcd — cluster datastore logs, topology, and TLS/at-rest posture (on-prem exclusive).

The cluster's datastore holds every Secret in the cluster, so this collector records its
security posture: is client certificate auth enforced, is it listening on a non-loopback
address, is encryption at rest configured, what does the on-disk data directory look like,
and which TLS material is in play.

**Not every distribution uses etcd**, and the difference matters:

* **kubeadm** — etcd as a static pod. Flags from ``/etc/kubernetes/manifests/etcd.yaml``,
  data under ``/var/lib/etcd``, TLS under ``/etc/kubernetes/pki/etcd``, logs from
  ``/var/log/pods/kube-system_etcd-*`` or ``journalctl -u etcd``.
* **k3s** — either embedded etcd at ``/var/lib/rancher/k3s/server/db/etcd`` or, by default, a
  **sqlite** datastore at ``/var/lib/rancher/k3s/server/db/state.db`` via kine. A sqlite
  datastore has no client-certificate model at all, so file permissions are the whole access
  control and "is cert auth on" is the wrong question. Datastore events live in the k3s
  server journal (``journalctl -u k3s``), which this collector reads when there is no
  separate etcd static-pod log.
* **RKE2** — embedded etcd under ``/var/lib/rancher/rke2/server/db/etcd``.
* **microk8s** — **dqlite** under ``/var/snap/microk8s/current/var/kubernetes/backend``.

Where ``etcdctl`` is available the collector also records cluster topology (``member list``)
and health (``endpoint health`` / ``endpoint status``), the member state an analyst needs to
know which node's datastore to trust.

It **never** dumps the datastore by default: it contains every Secret in the cluster in
plaintext unless encryption at rest is on. A dump is the explicit, separately-confirmed
``dump_db`` parameter and the resulting artifact is maximum-sensitivity. Private key material
is never copied, only inventoried and hashed.
"""

from __future__ import annotations

import contextlib
import json
import re
from typing import Any

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile
from collector.lib.params import param_bool, param_strings

from ..common.distro import DistroInfo, datastore_paths, datastore_tls_dirs
from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector

_ETCD_MANIFEST = "/etc/kubernetes/manifests/etcd.yaml"
_APISERVER_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
_ETCD_LOG_GLOB = "/var/log/pods/kube-system_etcd-*/*/*.log"
_ETCD_DATA_DIR = "/var/lib/etcd"
_ETCD_PKI_DIR = "/etc/kubernetes/pki/etcd"

_MANIFEST_FLAGS = (
    "client-cert-auth",
    "peer-client-cert-auth",
    "listen-client-urls",
    "advertise-client-urls",
    "listen-peer-urls",
    "data-dir",
    "cert-file",
    "key-file",
    "trusted-ca-file",
    "peer-cert-file",
    "peer-trusted-ca-file",
)

# Private key material is inventoried and hashed for tamper detection, never captured.
_KEY_SUFFIXES = (".key", ".pem.key")


class EtcdCollector(NodePlaneCollector):
    name = "k8s_etcd"
    priority = 2
    description = (
        "Cluster datastore posture and logs across etcd, k3s sqlite and microk8s dqlite "
        "(never dumps the datastore by default)."
    )
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        gaps: list[tuple[str, GapReason, str]] = []
        files: list[WrittenFile] = []

        distro = self.distro()
        posture = self._posture(node)
        for issue in posture.get("issues", []):
            gaps.append((self.name, GapReason.LOGGING_NOT_CONFIGURED, issue))

        # Which datastore this distribution actually runs, and where it keeps it.
        datastore = self._datastore(node, distro, posture)
        for issue in datastore.get("issues", []):
            gaps.append((self.name, GapReason.LOGGING_NOT_CONFIGURED, issue))

        # TLS material inventory (certs captured; keys hashed in place, never copied).
        pki = self._pki_inventory(files, distro)

        # On-disk data directory: existence, permissions, size — never contents.
        data_dir = self._data_dir_posture(
            node, posture.get("flags", {}).get("data-dir", "") or datastore.get("path", "")
        )

        # Logs: static pod first, then a dedicated etcd unit, then (on merged distros) the
        # server journal that also carries datastore events (k3s / RKE2 / microk8s).
        records: list[dict[str, Any]] = []
        log_files = 0
        log_source = ""
        for path in node.iter_glob(_ETCD_LOG_GLOB):
            host_path = "/" + path.relative_to(node.root).as_posix()
            wf = self.copy_node_file(host_path, f"logs/{path.name}")
            if wf is not None:
                files.append(wf)
                log_files += 1
                log_source = _ETCD_LOG_GLOB
        if not log_files:
            units: list[str] = ["etcd"]
            if distro.merged_control_plane:
                units = list(distro.server_units) or [distro.family]
            for unit in units:
                journal = collect_unit(
                    node, unit, fallback_files=("/var/log/etcd.log",) if unit == "etcd" else ()
                )
                if not (journal["available"] and journal["records"]):
                    continue
                records = journal["records"]
                log_source = journal["source"]
                if distro.merged_control_plane and unit != "etcd":
                    log_source = (
                        f"{journal['source']} (merged {distro.family} server unit; "
                        "no separate etcd journal on this node)"
                    )
                for rec in records:
                    nc.stamp(rec)
                    distro.stamp(rec)
                files.append(self.write_jsonl(records, "etcd.jsonl.gz"))
                break

        # Cluster topology + health (read-only etcdctl verbs).
        topology = self._topology(node, posture.get("flags", {}))
        if topology.get("unhealthy_endpoints"):
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "etcd endpoint(s) reported unhealthy: "
                    + ", ".join(topology["unhealthy_endpoints"]),
                )
            )

        db_dumped = False
        self._snapshot_file: WrittenFile | None = None
        if param_bool(self.artifact_params(), "dump_db"):
            db_dumped = self._maybe_dump_db(node, gaps, posture.get("flags", {}))
            if self._snapshot_file is not None:
                files.append(self._snapshot_file)

        files.append(
            self.write_json(
                {
                    "distro": distro.to_dict(),
                    "datastore": datastore,
                    "log_source": log_source,
                    "posture": posture,
                    "data_dir": data_dir,
                    "tls_material": pki,
                    "topology": topology,
                    "log_files": log_files,
                    "db_dumped": db_dumped,
                    "node": nc.to_dict(),
                },
                "config.json",
            )
        )
        self.write_meta(
            {
                "source": self.name,
                "distro": distro.family,
                "datastore": datastore.get("kind", "unknown"),
                "posture_issues": len(posture.get("issues", []))
                + len(datastore.get("issues", [])),
            }
        )

        collected = bool(
            log_files
            or records
            or posture.get("determined")
            or pki.get("files")
            or datastore.get("present")
        )
        status = SourceStatus.PARTIAL if gaps and collected else (
            SourceStatus.COLLECTED if collected else SourceStatus.EMPTY
        )
        if not collected and not gaps:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    f"No cluster datastore found on this {distro.family} {distro.role} node. "
                    f"Looked for: {', '.join(datastore.get('searched') or [])}. On a worker or "
                    "a managed control plane there is nothing to collect here; run this on a "
                    "control-plane or server node.",
                )
            )
            status = SourceStatus.EMPTY
        issue_count = len(posture.get("issues", [])) + len(datastore.get("issues", []))
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{distro.family} datastore={datastore.get('kind', 'unknown')}: "
            f"{issue_count} posture issue(s); {topology.get('member_count', 0)} member(s); "
            f"db_dumped={db_dumped}.",
        )

    # -- posture --------------------------------------------------------------------------

    def _posture(self, node: Any) -> dict[str, Any]:
        """etcd flags from the kubeadm static pod manifest, when that is how it runs."""
        out: dict[str, Any] = {"determined": False, "issues": [], "flags": {}}
        if not node.exists(_ETCD_MANIFEST):
            # A missing etcd manifest is only a finding where one was expected. On k3s, RKE2
            # and microk8s there is none by design, and on a worker or managed node there is
            # no control plane at all - in both cases its absence is a fact about the layout,
            # not evidence of anything. _datastore describes what is actually there.
            distro = self.distro()
            if not distro.merged_control_plane and distro.is_control_plane:
                out["issues"].append(
                    "etcd static pod manifest not found on this control-plane node, so etcd "
                    "flag posture is undetermined (external etcd, or a non-static-pod layout)."
                )
            out["encryption_at_rest"] = self._encryption_at_rest(node)
            return out
        try:
            text = node.read_text(_ETCD_MANIFEST)
        except Exception as exc:  # noqa: BLE001
            out["issues"].append(f"could not read etcd manifest: {exc}")
            return out
        out["determined"] = True
        flags = {}
        for flag in _MANIFEST_FLAGS:
            m = re.search(rf"--{re.escape(flag)}[= ]([^\s\"']+)", text)
            if m:
                flags[flag] = m.group(1)
        out["flags"] = flags

        if flags.get("client-cert-auth", "").lower() != "true":
            out["issues"].append(
                "etcd client certificate auth is NOT enforced (--client-cert-auth != true). "
                "Any client that can reach etcd has full cluster control."
            )
        if flags.get("peer-client-cert-auth", "").lower() not in ("", "true"):
            out["issues"].append(
                "etcd peer client certificate auth is disabled (--peer-client-cert-auth=false)."
            )
        listen = flags.get("listen-client-urls", "")
        if listen and not all(_is_loopback(u) for u in listen.split(",")):
            out["issues"].append(
                f"etcd is listening on a non-loopback address ({listen}). Direct etcd access "
                "from anything other than the API server is total cluster compromise."
            )
        if not flags.get("cert-file") or not flags.get("trusted-ca-file"):
            out["issues"].append(
                "etcd TLS is incompletely configured (missing --cert-file and/or "
                "--trusted-ca-file) — client traffic may be unencrypted."
            )

        encryption = self._encryption_at_rest(node)
        out["encryption_at_rest"] = encryption
        if encryption["determined"] and not encryption["enabled"]:
            out["issues"].append(
                "Kubernetes encryption-at-rest is NOT configured (no "
                "--encryption-provider-config on kube-apiserver): every Secret in the cluster "
                "is stored in etcd in plaintext. An etcd file-level read is total credential "
                "compromise."
            )
        return out

    def _datastore(
        self, node: Any, distro: DistroInfo, posture: dict[str, Any]
    ) -> dict[str, Any]:
        """Find the cluster datastore and describe what kind of protection it can even have.

        etcd, sqlite (k3s/kine) and dqlite (microk8s) are not interchangeable: only etcd has
        a client-certificate model, so on the others the file mode *is* the access control
        and that is what gets reported.
        """
        out: dict[str, Any] = {
            "kind": "unknown",
            "path": "",
            "present": False,
            "searched": [],
            "issues": [],
        }
        encryption = posture.get("encryption_at_rest") or self._encryption_at_rest(node)

        for candidate in datastore_paths(distro):
            path = candidate["path"]
            out["searched"].append(path)
            try:
                exists = node.exists(path)
            except Exception:  # noqa: BLE001
                continue
            if not exists:
                continue
            out["kind"] = candidate["kind"]
            out["path"] = path
            out["present"] = True
            break

        if not out["present"]:
            return out

        try:
            stat = node.resolve(out["path"]).stat()
            out["mode"] = oct(stat.st_mode & 0o777)
            out["uid"] = stat.st_uid
            out["gid"] = stat.st_gid
        except OSError:
            pass

        if out["kind"] in ("sqlite", "dqlite"):
            out["client_cert_auth_applicable"] = False
            out["note"] = (
                f"{distro.family} stores cluster state in {out['kind']} at {out['path']}, not "
                "etcd. There is no client-certificate model for this datastore, so the file "
                "permissions are the entire access control."
            )
            mode = out.get("mode")
            if mode and mode not in ("0o600", "0o640", "0o700"):
                out["issues"].append(
                    f"The {out['kind']} cluster datastore at {out['path']} is mode {mode}. "
                    "Any local user who can read that file can read every Secret in the "
                    "cluster; it should not be group or world readable."
                )
            if not (encryption or {}).get("enabled"):
                out["issues"].append(
                    f"Encryption at rest is not configured, so every Secret in the cluster is "
                    f"stored in plaintext in the {out['kind']} datastore at {out['path']}. "
                    "A single file read is total credential compromise."
                )
        else:
            out["client_cert_auth_applicable"] = True
            out["note"] = f"{distro.family} uses etcd at {out['path']}."
        return out

    @staticmethod
    def _encryption_at_rest(node: Any) -> dict[str, Any]:
        """Is ``--encryption-provider-config`` set on kube-apiserver? Determines etcd at-rest risk."""
        out: dict[str, Any] = {"determined": False, "enabled": False, "config_file": ""}
        if not node.exists(_APISERVER_MANIFEST):
            return out
        try:
            text = node.read_text(_APISERVER_MANIFEST)
        except Exception:  # noqa: BLE001
            return out
        out["determined"] = True
        m = re.search(r"--encryption-provider-config[= ]([^\s\"']+)", text)
        if m:
            out["enabled"] = True
            out["config_file"] = m.group(1)
        return out

    # -- TLS material + data dir ----------------------------------------------------------

    def _pki_inventory(self, files: list[WrittenFile], distro: DistroInfo) -> dict[str, Any]:
        """Inventory the datastore's TLS directory: capture certs, hash keys without copying.

        The directory is distro-specific (``/etc/kubernetes/pki/etcd`` on kubeadm,
        ``/var/lib/rancher/<distro>/server/tls/etcd`` on k3s and RKE2). microk8s dqlite has
        no such directory, and that is recorded rather than reported as missing.
        """
        from collector.lib.chain_of_custody.hashing import sha256_file

        node = self.node
        dirs = datastore_tls_dirs(distro)
        out: dict[str, Any] = {"dir": "", "searched": dirs, "present": False, "files": []}
        pki_dir = next((d for d in dirs if node.is_dir(d)), "")
        out["dir"] = pki_dir or (dirs[0] if dirs else "")
        if not pki_dir:
            if not dirs:
                out["note"] = (
                    f"{distro.family} does not use a certificate-authenticated datastore, so "
                    "there is no datastore TLS material to inventory."
                )
            return out
        out["present"] = True
        for path in sorted(node.resolve(pki_dir).rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            host_path = "/" + path.relative_to(node.root).as_posix()
            try:
                stat = path.stat()
            except OSError:
                continue
            entry: dict[str, Any] = {
                "path": host_path,
                "bytes": stat.st_size,
                "mode": oct(stat.st_mode & 0o777),
                "uid": stat.st_uid,
                "gid": stat.st_gid,
                "captured": False,
            }
            if host_path.endswith(_KEY_SUFFIXES):
                # Private key: hashed for tamper detection, contents never leave the node.
                with contextlib.suppress(OSError):
                    entry["sha256"] = sha256_file(path)
                entry["note"] = "private key — hashed only, contents not captured"
            else:
                rel = path.relative_to(node.resolve(pki_dir)).as_posix()
                wf = self.capture_path(path, f"pki/{rel.replace('/', '__')}")
                if wf is not None:
                    files.append(wf)
                    entry["sha256"] = wf.sha256
                    entry["captured"] = True
            out["files"].append(entry)
        return out

    @staticmethod
    def _data_dir_posture(node: Any, configured: str) -> dict[str, Any]:
        """Existence, permissions and size of the etcd data dir — never its contents."""
        host_dir = configured or _ETCD_DATA_DIR
        out: dict[str, Any] = {"path": host_dir, "present": False}
        resolved = node.resolve(host_dir)
        if not resolved.is_dir():
            return out
        out["present"] = True
        try:
            stat = resolved.stat()
            out["mode"] = oct(stat.st_mode & 0o777)
            out["uid"] = stat.st_uid
            out["gid"] = stat.st_gid
        except OSError:
            pass
        total = 0
        entries: list[dict[str, Any]] = []
        for path in sorted(resolved.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            total += size
            if len(entries) < 200:
                entries.append(
                    {"path": "/" + path.relative_to(node.root).as_posix(), "bytes": size}
                )
        out["total_bytes"] = total
        out["files"] = entries
        out["note"] = (
            "Contents intentionally NOT captured — the etcd database holds every Secret in the "
            "cluster in plaintext unless encryption-at-rest is enabled. Use dump_db to opt in."
        )
        if (stat_mode := out.get("mode")) and stat_mode not in ("0o700", "0o600"):
            out["warning"] = (
                f"etcd data directory is mode {stat_mode}; it should be 0700 — a wider mode "
                "means any local user can read every Secret in the cluster."
            )
        return out

    # -- topology / health ----------------------------------------------------------------

    def _topology(self, node: Any, flags: dict[str, str]) -> dict[str, Any]:
        """``etcdctl member list`` + ``endpoint health``/``status`` — read-only verbs only."""
        out: dict[str, Any] = {"available": False, "member_count": 0, "unhealthy_endpoints": []}
        if not node.have("etcdctl"):
            out["note"] = "etcdctl not available on node; topology and health undetermined."
            return out

        base = self._etcdctl_flags(flags)
        out["available"] = True
        out["endpoints"] = base.get("endpoints", "")

        members = self._etcdctl_json(node, base, ["member", "list"])
        if members is not None:
            out["members"] = members
            out["member_count"] = len((members or {}).get("members") or [])

        health = self._etcdctl_json(node, base, ["endpoint", "health", "--cluster"])
        if health is None:
            health = self._etcdctl_json(node, base, ["endpoint", "health"])
        if health is not None:
            out["health"] = health
            for row in health if isinstance(health, list) else []:
                if isinstance(row, dict) and not row.get("health", True):
                    out["unhealthy_endpoints"].append(str(row.get("endpoint", "unknown")))

        status = self._etcdctl_json(node, base, ["endpoint", "status", "--cluster"])
        if status is None:
            status = self._etcdctl_json(node, base, ["endpoint", "status"])
        if status is not None:
            out["status"] = status
            out["leader"] = _leader_from_status(status)
        return out

    def _etcdctl_flags(self, flags: dict[str, str]) -> dict[str, str]:
        """TLS + endpoint flags for etcdctl, from the manifest and the ``etcdctl_endpoints`` param."""
        override = param_strings(self.artifact_params(), "etcdctl_endpoints")
        endpoints = ",".join(override) if override else (
            flags.get("advertise-client-urls") or flags.get("listen-client-urls") or
            "https://127.0.0.1:2379"
        )
        out = {"endpoints": endpoints}
        for flag, key in (
            ("trusted-ca-file", "cacert"),
            ("cert-file", "cert"),
            ("key-file", "key"),
        ):
            if flags.get(flag):
                out[key] = flags[flag]
        return out

    @staticmethod
    def _etcdctl_json(node: Any, base: dict[str, str], verb: list[str]) -> Any:
        args = ["etcdctl", *verb, "--endpoints", base["endpoints"], "-w", "json"]
        for key in ("cacert", "cert", "key"):
            if base.get(key):
                args.extend([f"--{key}", base[key]])
        rc, out, _ = node.run(args, timeout=60)
        if rc != 0 or not out.strip():
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"_raw": out.strip()}

    # -- opt-in DB snapshot ---------------------------------------------------------------

    def _maybe_dump_db(self, node: Any, gaps: list, flags: dict[str, str]) -> bool:
        """Explicit, separately-confirmed etcd snapshot. Maximum sensitivity.

        ``etcdctl snapshot save`` must write the DB somewhere. We point it straight at the
        collector's own staging dir (never a host path — the host mount is read-only, and
        writing to the node would be a side effect), then hash the resulting file in place.
        """
        from collector.lib.chain_of_custody.hashing import sha256_file

        dest = self.ctx.source_dir(self.name) / "etcd-snapshot.db"
        dest.parent.mkdir(parents=True, exist_ok=True)
        base = self._etcdctl_flags(flags)
        args = ["etcdctl", "snapshot", "save", str(dest), "--endpoints", base["endpoints"]]
        for key in ("cacert", "cert", "key"):
            if base.get(key):
                args.extend([f"--{key}", base[key]])
        rc, _out, err = node.run(args, timeout=300)
        if rc != 0 or not dest.exists():
            gaps.append((self.name, GapReason.NOT_SUPPORTED, f"etcd snapshot failed: {err.strip()}"))
            return False
        self._snapshot_file = WrittenFile(
            path=dest.relative_to(self.ctx.staging).as_posix(),
            sha256=sha256_file(dest),
            bytes=dest.stat().st_size,
        )
        return True


def _leader_from_status(status: Any) -> str:
    """Pull the leader member id out of ``endpoint status -w json`` output."""
    rows = status if isinstance(status, list) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        header = (row.get("Status") or {}).get("header") or {}
        leader = (row.get("Status") or {}).get("leader")
        if leader and header.get("member_id") == leader:
            return str(row.get("Endpoint", "")) or str(leader)
    for row in rows:
        if isinstance(row, dict):
            leader = (row.get("Status") or {}).get("leader")
            if leader:
                return str(leader)
    return ""


def _is_loopback(url: str) -> bool:
    url = url.strip().lower()
    return "127.0.0.1" in url or "localhost" in url or "[::1]" in url
