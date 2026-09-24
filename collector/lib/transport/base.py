"""Transport adapters. Default is ``local`` — the collector never ships anything off-box
unless the operator explicitly chooses a remote transport."""

from __future__ import annotations

import abc
from pathlib import Path
from urllib.parse import urlparse


class Transport(abc.ABC):
    @abc.abstractmethod
    def deliver(self, package_path: Path) -> str:
        """Deliver the package; return a human-readable location string."""


class LocalTransport(Transport):
    """No-op: the package stays where it was written. The operator hand-carries it."""

    def deliver(self, package_path: Path) -> str:
        return str(package_path.resolve())


class S3PresignedTransport(Transport):
    """PUT the package to a presigned URL supplied by the IR team.

    Uses urllib so it has no extra dependency. The URL is opaque and account-agnostic, so
    this works even when the collector's own credentials can't reach the IR bucket.
    """

    def __init__(self, url: str) -> None:
        self.url = url

    def deliver(self, package_path: Path) -> str:
        import urllib.request

        req = urllib.request.Request(self.url, method="PUT")
        req.add_header("Content-Type", "application/zstd")
        with package_path.open("rb") as body:
            with urllib.request.urlopen(req, data=body, timeout=3600) as resp:  # noqa: S310
                status = resp.status
        if status not in (200, 204):
            raise RuntimeError(f"Upload failed with HTTP {status}")
        return f"uploaded to presigned URL (HTTP {status})"


class S3Transport(Transport):
    """Upload a sealed package to S3 using operator IAM credentials (multipart for large files)."""

    def __init__(self, bucket: str, prefix: str = "", *, region: str | None = None) -> None:
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.region = region

    def deliver(self, package_path: Path) -> str:
        try:
            import boto3
            from boto3.s3.transfer import TransferConfig
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("S3 transport requires boto3 (pip install boto3)") from exc

        client = boto3.client("s3", region_name=self.region or None)
        key = f"{self.prefix}/{package_path.name}" if self.prefix else package_path.name
        config = TransferConfig(
            multipart_threshold=64 * 1024 * 1024,
            multipart_chunksize=64 * 1024 * 1024,
        )
        client.upload_file(str(package_path), self.bucket, key, Config=config)
        sidecar = package_path.parent / f"{package_path.name}.sha256"
        if sidecar.is_file():
            sidecar_key = f"{self.prefix}/{sidecar.name}" if self.prefix else sidecar.name
            client.upload_file(str(sidecar), self.bucket, sidecar_key, Config=config)
        return f"s3://{self.bucket}/{key}"


class SftpTransport(Transport):
    """Push to an SFTP drop. Imports paramiko lazily so the base install stays light."""

    def __init__(self, host: str, path: str, username: str, key_path: str | None = None) -> None:
        self.host = host
        self.path = path
        self.username = username
        self.key_path = key_path

    def deliver(self, package_path: Path) -> str:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("SFTP transport requires 'paramiko' (pip install paramiko)") from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.load_system_host_keys()
        kwargs = {"username": self.username}
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        client.connect(self.host, **kwargs)
        sftp = client.open_sftp()
        remote = f"{self.path.rstrip('/')}/{package_path.name}"
        sftp.put(str(package_path), remote)
        sftp.close()
        client.close()
        return f"sftp://{self.host}{remote}"


def get_transport(spec: str | None) -> Transport:
    """Build a transport from a CLI spec.

    Examples: ``local`` (default), ``s3://bucket/prefix/``, ``s3-presigned:<url>``,
    ``sftp:user@host:/path``.
    """
    if not spec or spec == "local":
        return LocalTransport()
    if spec.startswith("s3-presigned:"):
        return S3PresignedTransport(spec.split(":", 1)[1])
    if spec.startswith("s3://"):
        parsed = urlparse(spec)
        bucket = parsed.netloc
        prefix = parsed.path.lstrip("/")
        if not bucket:
            raise ValueError(f"Invalid S3 transport spec (missing bucket): {spec!r}")
        return S3Transport(bucket, prefix)
    if spec.startswith("sftp:"):
        rest = spec.split(":", 1)[1]
        userhost, path = rest.split(":", 1)
        username, host = userhost.split("@", 1)
        return SftpTransport(host=host, path=path, username=username)
    raise ValueError(f"Unknown transport spec: {spec!r}")
