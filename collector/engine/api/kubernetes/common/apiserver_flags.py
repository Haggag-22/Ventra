"""Resolve kube-apiserver flags from whatever this distribution uses to declare them.

Every audit question Ventra asks — is auditing on, where is the log, what does the policy
cover, is encryption at rest configured, how long do Events live — comes down to reading
kube-apiserver's flags. Only kubeadm puts them in a static pod manifest:

* **kubeadm** — ``/etc/kubernetes/manifests/kube-apiserver.yaml``, flags as ``--flag=value``
  in the container command.
* **RKE2** — the same shape, but under ``/var/lib/rancher/rke2/agent/pod-manifests``, plus
  ``/etc/rancher/rke2/config.yaml`` holding ``kube-apiserver-arg`` entries.
* **k3s** — no manifest at all. Flags live in ``/etc/rancher/k3s/config.yaml`` as
  ``kube-apiserver-arg: [audit-log-path=...]`` and/or on the unit's ``ExecStart`` line.
* **microk8s** — one flag per line in ``/var/snap/microk8s/current/args/kube-apiserver``.

So the value may be written ``--audit-log-path=/x``, ``--audit-log-path /x``,
``audit-log-path=/x`` or ``audit-log-path: /x``. All four are accepted, sources are tried in
distro order, the first source to define a flag wins, and the caller is told which files were
searched so an unresolved flag can be reported honestly rather than guessed at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .distro import DistroInfo, apiserver_flag_sources

# Flags Ventra reads. Kept explicit: this is evidence resolution, not a config parser.
AUDIT_FLAGS = (
    "audit-log-path",
    "audit-policy-file",
    "audit-log-maxage",
    "audit-log-maxbackup",
    "audit-log-maxsize",
    "audit-webhook-config-file",
    "encryption-provider-config",
    "event-ttl",
)


@dataclass
class ApiserverFlags:
    """Flags found, where each came from, and everything that was looked at."""

    flags: dict[str, str] = field(default_factory=dict)
    origins: dict[str, str] = field(default_factory=dict)
    # Every candidate path considered, whether or not it existed.
    searched: list[str] = field(default_factory=list)
    # Candidates that were actually read. A source that is readable but declares no audit
    # flags is still conclusive: it proves the flags are absent rather than unknown.
    readable: list[str] = field(default_factory=list)
    # Candidates that contributed at least one flag value.
    found_in: list[str] = field(default_factory=list)

    def get(self, flag: str, default: str = "") -> str:
        return self.flags.get(flag, default)

    @property
    def determined(self) -> bool:
        """True when at least one kube-apiserver flag source could be read."""
        return bool(self.readable)

    @property
    def evidence(self) -> list[str]:
        """The sources worth naming in a finding: those that defined flags, else those read."""
        return self.found_in or self.readable

    def to_dict(self) -> dict[str, Any]:
        return {
            "flags": dict(self.flags),
            "origins": dict(self.origins),
            "searched": list(self.searched),
            "readable": list(self.readable),
            "found_in": list(self.found_in),
            "determined": self.determined,
        }


def _patterns(flag: str) -> tuple[re.Pattern[str], ...]:
    escaped = re.escape(flag)
    return (
        # kubeadm / RKE2 manifest and microk8s args: --flag=value or --flag value
        re.compile(rf"--{escaped}[=\s]+([^\s\"',]+)"),
        # k3s / RKE2 config.yaml: "- audit-log-path=value" or "audit-log-path: value"
        re.compile(rf"(?<![\w-]){escaped}\s*[:=]\s*([^\s\"',]+)"),
    )


def parse_flags(text: str, flags: tuple[str, ...] = AUDIT_FLAGS) -> dict[str, str]:
    """Extract known flags from one config file, unit file, or manifest."""
    out: dict[str, str] = {}
    for flag in flags:
        for pattern in _patterns(flag):
            match = pattern.search(text)
            if match:
                out[flag] = match.group(1)
                break
    return out


def read_apiserver_flags(
    node: Any, distro: DistroInfo, *, flags: tuple[str, ...] = AUDIT_FLAGS
) -> ApiserverFlags:
    """Read kube-apiserver flags from every source this distribution might use.

    Never raises: an unreadable candidate is skipped and still recorded in ``searched``.
    """
    out = ApiserverFlags()
    for path in apiserver_flag_sources(distro):
        out.searched.append(path)
        try:
            if not node.exists(path) or node.is_dir(path):
                continue
            text = node.read_text(path)
        except Exception:  # noqa: BLE001 - an unreadable candidate is not fatal
            continue
        out.readable.append(path)
        found = parse_flags(text, flags)
        if not found:
            continue
        contributed = False
        for flag, value in found.items():
            if flag not in out.flags:
                out.flags[flag] = value
                out.origins[flag] = path
                contributed = True
        if contributed and path not in out.found_in:
            out.found_in.append(path)
    return out
