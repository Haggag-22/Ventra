"""Watch an S3 prefix for new sealed packages and ingest them."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse


@dataclass
class S3IngestItem:
    s3_key: str
    case_id: str
    event_count: int
    integrity: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class S3IngestResult:
    ingested: list[S3IngestItem] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    skipped: int = 0


def _parse_s3_prefix(spec: str) -> tuple[str, str]:
    parsed = urlparse(spec if "://" in spec else f"s3://{spec}")
    if parsed.scheme != "s3" or not parsed.netloc:
        raise ValueError(f"Expected s3://bucket/prefix, got {spec!r}")
    return parsed.netloc, parsed.path.lstrip("/")


def _list_packages(bucket: str, prefix: str) -> list[str]:
    import boto3

    client = boto3.client("s3")
    keys: list[str] = []
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents") or []:
            key = obj.get("Key") or ""
            if key.endswith(".tar.zst") or key.endswith(".tar.gz"):
                keys.append(key)
    return sorted(keys)


def _download_package(bucket: str, key: str, dest: Path) -> Path:
    import boto3

    dest.parent.mkdir(parents=True, exist_ok=True)
    boto3.client("s3").download_file(bucket, key, str(dest))
    return dest


def poll_s3_once(
    s3_prefix: str,
    case_store: Path,
    *,
    download_dir: Path | None = None,
    state_file: Path | None = None,
    reporter: Callable[[str], Any] | None = None,
) -> S3IngestResult:
    """Poll an S3 prefix once and ingest any new sealed packages."""
    from .pipeline import ingest_package

    bucket, prefix = _parse_s3_prefix(s3_prefix)
    case_store = Path(case_store)
    dl_dir = Path(download_dir or case_store.parent / ".ventra-ingest-watch")
    dl_dir.mkdir(parents=True, exist_ok=True)
    state_path = Path(state_file or (dl_dir / "ingested-keys.json"))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    if state_path.is_file():
        seen = set(json.loads(state_path.read_text(encoding="utf-8")))

    out = S3IngestResult()
    for key in _list_packages(bucket, prefix):
        if key in seen:
            out.skipped += 1
            continue
        local = dl_dir / Path(key).name
        if reporter:
            reporter(f"Downloading s3://{bucket}/{key}")
        try:
            _download_package(bucket, key, local)
            result = ingest_package(local, case_store, reporter=reporter)
            seen.add(key)
            state_path.write_text(json.dumps(sorted(seen), indent=2), encoding="utf-8")
            out.ingested.append(
                S3IngestItem(
                    s3_key=key,
                    case_id=result.case_id,
                    event_count=result.event_count,
                    integrity=result.integrity_overall,
                    warnings=list(result.warnings),
                )
            )
        except Exception as exc:  # noqa: BLE001
            out.errors.append({"s3_key": key, "error": str(exc)})
            if reporter:
                reporter(f"Failed s3://{bucket}/{key}: {exc}")
    return out


def ingest_watch_main(argv: list[str] | None = None) -> int:
    from . import __version__

    p = argparse.ArgumentParser(
        prog="ventra-ingest-watch",
        description="Poll an S3 evidence prefix and ingest new sealed packages.",
    )
    p.add_argument("--s3-prefix", required=True, help="s3://bucket/prefix/ to watch.")
    p.add_argument("--case-store", default="./cases", help="Case store root.")
    p.add_argument("--download-dir", default="./.ventra-ingest-watch", help="Local staging dir.")
    p.add_argument("--state-file", default=None, help="JSON file tracking ingested S3 keys.")
    p.add_argument("--poll-interval", type=int, default=60, help="Seconds between polls.")
    p.add_argument("--once", action="store_true", help="Poll once and exit.")
    p.add_argument("--version", action="version", version=f"ventra-ingester {__version__}")
    args = p.parse_args(argv)

    say = _reporter()
    while True:
        poll_s3_once(
            args.s3_prefix,
            Path(args.case_store),
            download_dir=Path(args.download_dir),
            state_file=Path(args.state_file) if args.state_file else None,
            reporter=say,
        )
        if args.once:
            break
        time.sleep(max(5, args.poll_interval))
    return 0


def _reporter():
    try:
        from rich.console import Console

        console = Console()
        return console.print
    except Exception:  # pragma: no cover
        return print


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(ingest_watch_main())
