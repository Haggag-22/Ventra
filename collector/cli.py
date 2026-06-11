"""Harbor command-line interface.

    harbor collect aws --case CASE-2026-0042 \
        --since 2026-05-11 --regions us-east-1,us-west-2 --out ./harbor-evidence

The CLI is deliberately thin: it parses arguments, builds an AwsRunConfig, and delegates to
the runner. All forensic logic lives in the collectors and the runner.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .lib.transport import get_transport


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harbor",
        description="Harbor — read-only cloud forensic triage.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"harbor-collector {__version__}",
    )
    sub = p.add_subparsers(dest="command", required=True)

    collect = sub.add_parser(
        "collect",
        help="Collect evidence from a cloud (read-only, all registered collectors).",
    )
    cloud_sub = collect.add_subparsers(dest="cloud", required=True)

    aws = cloud_sub.add_parser("aws", help="Collect from AWS.")
    aws.add_argument("--case", help="Case identifier, e.g. CASE-2026-0042.")
    aws.add_argument("--engagement", default="", help="Optional engagement/matter id.")
    aws.add_argument("--regions", default="", help="Comma-separated regions (default: all enabled).")
    aws.add_argument("--since", default=None, help="Window start (YYYY-MM-DD or RFC3339 UTC).")
    aws.add_argument("--until", default=None, help="Window end (YYYY-MM-DD or RFC3339 UTC).")
    aws.add_argument("--out", default="./harbor-evidence", help="Output directory for the package.")
    aws.add_argument("--transport", default="local", help="local | s3-presigned:<url> | sftp:...")
    aws.add_argument("--key", default=None, help="Signing key path for cosign/minisign.")
    aws.add_argument("--list-collectors", action="store_true", help="List collectors and exit.")
    return p


def _cli_reporter():
    """A rich-backed reporter when rich is available, else a plain-text one."""
    try:
        from rich.console import Console

        from .aws.runner.runner import RunReporter

        console = Console()

        class RichReporter(RunReporter):
            def _emit(self, name, status):
                color = {
                    "running": "yellow",
                    "collected": "green",
                    "empty": "blue",
                    "partial": "cyan",
                    "errored": "red",
                    "skipped": "dim",
                }.get(status, "white")
                console.print(f"  [{color}]{status:<10}[/{color}] {name}")

        return RichReporter(), console
    except Exception:  # pragma: no cover
        from .aws.runner.runner import RunReporter

        return RunReporter(), None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "collect" and args.cloud == "aws":
        return _run_aws(args)
    print(f"Command {args.command!r} is not implemented.", file=sys.stderr)
    return 2


def _run_aws(args) -> int:
    from .aws.registry import AWS_REGISTRY, all_collector_names
    from .aws.runner.runner import AwsRunConfig, parse_window, run_aws_collection

    if args.list_collectors:
        for name, cls in sorted(AWS_REGISTRY.all().items()):
            print(f"  tier{cls.tier}  {name:<14} {cls.description}")
        return 0

    if not args.case:
        print("error: --case is required to run a collection.", file=sys.stderr)
        return 2

    collectors = all_collector_names()
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] or None
    window = parse_window(args.since, args.until)

    reporter, console = _cli_reporter()
    if console:
        console.rule(f"[bold]Harbor[/bold] · case {args.case}")
        console.print(f"Collectors ({len(collectors)}): {', '.join(collectors)}\n")

    cfg = AwsRunConfig(
        case_id=args.case,
        collectors=collectors,
        regions=regions,
        time_window=window,
        out_dir=Path(args.out),
        engagement_id=args.engagement,
        key_path=Path(args.key) if args.key else None,
        reporter=reporter,
    )

    try:
        package = run_aws_collection(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"\nCollection failed: {exc}", file=sys.stderr)
        return 1

    msg = (
        f"\nSealed package: {package.path}\n"
        f"  compression: {package.compression}\n"
        f"  size:        {package.bytes:,} bytes\n"
        f"  sha256:      {package.sha256}\n"
    )
    if console:
        console.print(msg)
    else:
        print(msg)

    try:
        location = get_transport(args.transport).deliver(package.path)
        print(f"Delivered: {location}")
    except Exception as exc:  # noqa: BLE001
        print(f"Transport failed ({args.transport}): {exc}", file=sys.stderr)
        print(f"Package remains at {package.path}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
