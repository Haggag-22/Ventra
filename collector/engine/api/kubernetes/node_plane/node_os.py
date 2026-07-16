"""k8s_node_os — host-level Linux forensics.

If the attacker escaped the container, this is where you see it: auth logs, syslog/messages,
kernel ring buffer, account files, cron persistence, systemd units, SSH authorized_keys, and
login records. Account payloads are captured as metadata (``/etc/shadow`` is recorded as
present + hashed, never its hashes exposed in the record body).
"""

from __future__ import annotations

from typing import Any

from collector.lib.chain_of_custody.hashing import sha256_file
from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile

from ..common.nodebase import NodePlaneCollector


def _flat(host_path: str) -> str:
    """Flatten a host path into a single archive filename (``/a/b`` → ``a__b``)."""
    return host_path.lstrip("/").replace("/", "__")

# host_path -> archive destination. Distro variants handled by trying both.
_LOG_FILES = (
    "/var/log/auth.log",       # Debian/Ubuntu
    "/var/log/secure",         # RHEL/CentOS
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
)
_PERSISTENCE_GLOBS = (
    "/etc/cron.d/*",
    "/etc/cron.daily/*",
    "/etc/cron.hourly/*",
    "/etc/crontab",
    "/var/spool/cron/*",
    "/var/spool/cron/crontabs/*",
    "/etc/systemd/system/*.service",
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys",
)
_ACCOUNT_FILES = ("/etc/passwd", "/etc/group")


class NodeOsCollector(NodePlaneCollector):
    name = "k8s_node_os"
    priority = 2
    description = "Host Linux forensics: auth/syslog/kernel logs, cron, systemd, SSH keys, accounts."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        gaps: list[tuple[str, GapReason, str]] = []
        files: list[WrittenFile] = []
        captured: list[dict[str, Any]] = []

        for host_path in _LOG_FILES:
            wf = self.capture_file(host_path, f"logs/{_flat(host_path)}")
            if wf is not None:
                files.append(wf)
                captured.append({"path": host_path, "kind": "log", "sha256": wf.sha256})

        for glob in _PERSISTENCE_GLOBS:
            for path in node.iter_glob(glob):
                if not path.is_file():
                    continue
                host_path = "/" + path.relative_to(node.root).as_posix()
                wf = self.capture_path(path, f"persistence/{_flat(host_path)}")
                if wf is not None:
                    files.append(wf)
                    captured.append({"path": host_path, "kind": "persistence", "sha256": wf.sha256})

        # Accounts as full content (passwd/group are not secret); shadow as presence+hash only.
        for host_path in _ACCOUNT_FILES:
            wf = self.capture_file(host_path, f"accounts/{_flat(host_path)}")
            if wf is not None:
                files.append(wf)
                captured.append({"path": host_path, "kind": "account", "sha256": wf.sha256})
        shadow = self._shadow_metadata(node)

        # Kernel ring buffer via journalctl -k (best effort).
        rc, out, _ = node.run(["journalctl", "-k", "--no-pager", "-o", "short"])
        if rc == 0 and out.strip():
            files.append(self.write_node_bytes(out.encode("utf-8"), "logs/kernel.log"))
            captured.append({"path": "journalctl -k", "kind": "kernel"})

        files.append(
            self.write_json(
                {"captured": captured, "shadow": shadow, "node": nc.to_dict()}, "config.json"
            )
        )
        self.write_meta({"source": self.name, "captured": len(captured)})

        if not captured:
            gaps.append((self.name, GapReason.NOT_PRESENT, "No host OS forensic artifacts readable."))
            return SourceResult(
                name=self.name, status=SourceStatus.EMPTY, files=files, gaps=gaps,
                notes="No host artifacts.",
            )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(captured),
            gaps=gaps,
            notes=f"{len(captured)} host artifact(s) from {nc.node_name or 'node'}.",
        )

    def _shadow_metadata(self, node: Any) -> dict[str, Any]:
        """/etc/shadow presence + hash only — never expose the hashed passwords themselves."""
        src = node.resolve("/etc/shadow")
        if not src.is_file():
            return {"present": False}
        try:
            usernames = [
                ln.split(":", 1)[0]
                for ln in src.read_text(errors="replace").splitlines()
                if ln.strip()
            ]
        except OSError:
            usernames = []
        return {"present": True, "sha256": sha256_file(src), "usernames": usernames}
