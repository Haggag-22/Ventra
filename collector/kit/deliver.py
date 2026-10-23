"""Deliver a sealed kit package to the IR team via the transport set in the kit.

Acquire's enterprise profile writes a ``transport`` spec into the kit's ``acquisition.yaml``
(``s3://bucket/prefix/`` or ``s3-presigned:<url>``). ``ventra run`` reads it before collecting
so a bad spec fails fast, then hands the sealed package to :func:`deliver_package`.

S3 uploads use the host's own AWS credentials (environment as it was before the kit's were
applied, ``~/.aws``, instance role) — never the kit's collection credentials, which are
read-only by design and cannot write to the IR bucket.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from collector.lib.transport import Transport, get_transport
from collector.lib.transport.base import LocalTransport, S3Transport

from .format import KitError

# Environment variables ``_apply_aws_credentials`` overwrites with the kit's keys.
AWS_ENV_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE")


@dataclass
class Delivery:
    """Outcome of one delivery attempt. ``target`` is redacted and safe to log or store."""

    target: str
    location: str = ""
    error: str = ""


def redact_transport(spec: str) -> str:
    """Drop the signature from a presigned URL so the spec can go into custody records."""
    if not spec.startswith("s3-presigned:"):
        return spec
    parts = urlsplit(spec.split(":", 1)[1])
    return "s3-presigned:" + urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def kit_transport(acquisition_path: Path) -> tuple[str, Transport | None]:
    """Read and parse the kit's transport spec; a ``None`` transport keeps the package local.

    Raises :class:`KitError` for an unreadable acquisition.yaml or a spec ``get_transport``
    doesn't understand, so the run stops before collecting rather than after.
    """
    from collector.engine.acquisition import load_acquisition

    try:
        spec = load_acquisition(acquisition_path).transport
        transport = get_transport(spec)
    except Exception as exc:  # noqa: BLE001 - AcquisitionError, ValueError, YAML errors
        raise KitError(f"invalid transport in kit acquisition.yaml: {exc}") from None
    return spec, (None if isinstance(transport, LocalTransport) else transport)


def snapshot_aws_env() -> dict[str, str]:
    """Capture the host's AWS credential env vars before the kit's keys replace them."""
    return {k: os.environ[k] for k in AWS_ENV_KEYS if k in os.environ}


@contextlib.contextmanager
def _host_aws_env(host_env: Mapping[str, str]) -> Iterator[None]:
    """Temporarily put the host's AWS env vars back, restoring the kit's afterwards."""
    saved = snapshot_aws_env()
    for key in AWS_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(host_env)
    try:
        yield
    finally:
        for key in AWS_ENV_KEYS:
            os.environ.pop(key, None)
        os.environ.update(saved)


def deliver_package(
    transport: Transport,
    spec: str,
    package_path: Path,
    *,
    host_aws_env: Mapping[str, str],
) -> Delivery:
    """Ship ``package_path`` via ``transport``; failures are returned, never raised.

    The package stays on disk either way, so a failed upload can be retried or hand-carried.
    """
    delivery = Delivery(target=redact_transport(spec.strip()))
    try:
        with _host_aws_env(host_aws_env):
            if isinstance(transport, S3Transport):
                import boto3

                # A fresh session resolves credentials now, from the host env — not from
                # the default session, which may have cached the kit's keys.
                transport.session = boto3.session.Session()
            delivery.location = transport.deliver(package_path)
    except Exception as exc:  # noqa: BLE001 - reported to the operator, package kept
        delivery.error = str(exc) or type(exc).__name__
    return delivery
