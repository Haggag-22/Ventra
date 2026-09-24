"""Ventra collector — read-only cloud forensic triage acquisition.

The collector runs in the client's cloud shell, gathers exactly the logs and artifacts
incident responders need, and seals them into a signed evidence package described by the
Ventra Evidence Package Format (EPF).

Forensic invariant: nothing in this package may call a mutating cloud API. See
``collector.tools.verify_readonly`` and the ``readonly-guard`` CI check.
"""

import os as _os

# gRPC's default async c-ares DNS resolver fails with "DNS query cancelled" on macOS and behind
# VPNs/split-horizon DNS (it ignores the OS resolver config). Forcing the native OS resolver
# (getaddrinfo) fixes it. This MUST be set before grpc is imported — grpc reads GRPC_DNS_RESOLVER
# when its core initializes (during `from google.cloud import ...`), so the collector package
# root (which runs before any submodule that imports google) is the earliest reliable point.
# setdefault keeps an explicit operator override.
_os.environ.setdefault("GRPC_DNS_RESOLVER", "native")
del _os

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    # Resolved from the installed distribution's metadata, which setuptools-scm derives from
    # the git tag at build/install time. Recorded in every manifest as ``tool_version``, so an
    # evidence package always shows exactly which build collected it (a tagged release like
    # ``0.2.0``, or a dev build like ``0.2.0.dev3+g1a2b3c4`` when run from a working tree).
    __version__ = _pkg_version("ventra")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

del PackageNotFoundError, _pkg_version
