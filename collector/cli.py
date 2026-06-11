"""Harbor collector command-line interface.

    harbor-collect aws --case CASE-2026-0042 \
        --since 2026-05-11 --regions us-east-1,us-west-2 --out ./harbor-evidence

Runs every registered collector for the cloud. The CLI is deliberately thin: it parses
arguments, builds an AwsRunConfig, and delegates to the runner.

While a collection runs, the CLI renders a live "collection matrix" — one PASS / PARTIAL /
INFO / FAIL row per source as it completes — so the operator can see exactly what was
captured and what was missing (a gap is evidence). The same matrix is written to
``collection_matrix.csv`` in the output directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .lib.models import SourceStatus, utcnow_iso
from .lib.transport import get_transport


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harbor-collect",
        description="Read-only cloud forensic triage collector (Harbor).",
    )
    p.add_argument("--version", action="version", version=f"harbor-collector {__version__}")
    sub = p.add_subparsers(dest="cloud", required=True)

    aws = sub.add_parser("aws", help="Collect from AWS (the first supported cloud).")
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


# Per-source severity. Drives the PASS/FAIL/INFO classification: a *missing* High source
# (service not enabled / logging not configured) is a FAIL; a missing Medium/Low source is
# informational. This mirrors how a responder weighs a coverage gap.
_SEVERITY: dict[str, str] = {
    "account": "Low",
    "cloudtrail": "High",
    "sts": "Low",
    "iam": "High",
    "vpc_flow": "High",
    "waf": "Medium",
    "guardduty": "High",
    "macie": "Medium",
    "detective": "Medium",
    "config": "High",
    "securityhub": "High",
    "kms": "Medium",
    "secrets": "Medium",
    "ec2": "Medium",
    "s3": "Medium",
    "lambda": "Low",
}

_SEV_COLOR = {"High": "red", "Medium": "yellow", "Low": "cyan"}


def _classify(status: SourceStatus, severity: str) -> tuple[str, str]:
    """Map a collector outcome + severity to a (label, color) for the matrix."""
    if status == SourceStatus.COLLECTED:
        return "PASS", "green"
    if status == SourceStatus.PARTIAL:
        return "PART", "yellow"
    if status == SourceStatus.ERRORED:
        return "FAIL", "red"
    if status == SourceStatus.SKIPPED:
        return "SKIP", "bright_black"
    # EMPTY: a missing High-value source is a failure; otherwise informational.
    if severity == "High":
        return "FAIL", "red"
    return "INFO", "blue"


def _cli_reporter():
    """Build the live-matrix reporter. Returns (reporter, console_or_None)."""
    from .aws.registry import AWS_REGISTRY
    from .aws.runner.runner import RunReporter

    try:
        from rich.console import Console

        console = Console()
    except Exception:  # pragma: no cover - rich is a declared dependency
        console = None

    class MatrixReporter(RunReporter):
        """Streams one matrix row per source as it completes, with a live spinner."""

        def __init__(self) -> None:
            super().__init__()
            self.rows: list[dict] = []
            self._console = console
            self._status = None
            self._account = ""
            self._masked = "????"

        # -- lifecycle ------------------------------------------------------
        def begin_run(self, account_id: str, regions: list[str], case_id: str = "") -> None:
            self._account = account_id or ""
            self._masked = (account_id[:4] + "***") if account_id else "????"
            ts = utcnow_iso()
            if self._console:
                self._console.print()
                self._console.rule("[bold]Harbor[/bold] · Live Collection Matrix")
                self._console.print(f"Account ID : [bold]{self._masked}[/bold]")
                if case_id:
                    self._console.print(f"Case       : {case_id}")
                self._console.print(f"Scope      : Global / {len(regions)} region(s)")
                self._console.print(f"Timestamp  : {ts}")
                self._console.print()
                self._console.print(f"[+] Starting collection for account {self._masked}\n")
                self._status = self._console.status(
                    "[bright_black]initializing…[/bright_black]", spinner="dots"
                )
                self._status.start()
            else:
                print(f"[+] Harbor collection — account {self._masked} — {ts}")

        def start(self, name: str) -> None:
            if self._status:
                self._status.update(f"[yellow]collecting[/yellow] {name}…")

        def finish(self, name: str, result) -> None:
            row = self._build_row(name, result)
            self.rows.append(row)
            self._print_row(row)

        def stop(self) -> None:
            if self._status:
                self._status.stop()
                self._status = None

        def finalize(self) -> None:
            self.stop()
            from collections import Counter

            c = Counter(r["label"] for r in self.rows)
            if self._console:
                self._console.print(
                    f"\n[+] Collection complete: "
                    f"[green]{c.get('PASS', 0)} collected[/green], "
                    f"[yellow]{c.get('PART', 0)} partial[/yellow], "
                    f"[blue]{c.get('INFO', 0)} info[/blue], "
                    f"[red]{c.get('FAIL', 0)} fail[/red]"
                )
            else:
                print(
                    f"[+] Complete: {c.get('PASS', 0)} collected, {c.get('PART', 0)} partial, "
                    f"{c.get('INFO', 0)} info, {c.get('FAIL', 0)} fail"
                )

        def write_matrix_csv(self, out_dir) -> Path:
            import csv

            out = Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            path = out / "collection_matrix.csv"
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(
                    ["status", "account", "scope", "check", "severity", "records", "detail"]
                )
                for r in self.rows:
                    w.writerow(
                        [r["label"], self._account, r["scope"], r["check"],
                         r["severity"], r["tag"], r["desc"]]
                    )
            return path

        # -- row construction ----------------------------------------------
        def _build_row(self, name: str, result) -> dict:
            cls = AWS_REGISTRY.get(name)
            tier = getattr(cls, "tier", 2)
            severity = _SEVERITY.get(name, "High" if tier == 1 else "Medium")
            label, color = _classify(result.status, severity)

            count = result.record_count
            tag = f"{count:,}" if isinstance(count, int) else "-"

            if result.status != SourceStatus.COLLECTED and result.gaps:
                desc = result.gaps[0][2] or result.notes
            else:
                desc = result.notes or (cls.description if cls else "")

            return {
                "label": label,
                "color": color,
                "scope": "global",
                "check": name.upper(),
                "severity": severity,
                "sev_color": _SEV_COLOR.get(severity, "white"),
                "tag": tag,
                "desc": desc,
            }

        def _print_row(self, row: dict) -> None:
            if self._console:
                line = (
                    f"[bold {row['color']}]{row['label']:<5}[/] "
                    f"[bright_black]{self._masked:<8}[/] "
                    f"{row['scope']:<7} "
                    f"{row['check']:<13} "
                    f"[{row['sev_color']}]{row['severity']:<6}[/] "
                    f"{row['tag']:<12} "
                    f"{row['desc']}"
                )
                # Keep every source on a single line; truncate over-long detail with an
                # ellipsis rather than wrapping, so the matrix stays readable on any width.
                self._console.print(line, no_wrap=True, overflow="ellipsis", crop=True)
            else:
                print(
                    f"{row['label']:<5} {self._masked:<8} {row['scope']:<7} "
                    f"{row['check']:<13} {row['severity']:<6} {row['tag']:<12} {row['desc']}"
                )

    return MatrixReporter(), console


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cloud == "aws":
        return _run_aws(args)
    print(f"Cloud {args.cloud!r} is scaffolded but not yet implemented.", file=sys.stderr)
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
        reporter.stop()
        print(f"\nCollection failed: {exc}", file=sys.stderr)
        return 1

    reporter.finalize()
    try:
        csv_path = reporter.write_matrix_csv(args.out)
    except Exception:  # noqa: BLE001 - matrix is a convenience artifact, never fatal
        csv_path = None

    msg = (
        f"\nSealed package: {package.path}\n"
        f"  compression: {package.compression}\n"
        f"  size:        {package.bytes:,} bytes\n"
        f"  sha256:      {package.sha256}\n"
    )
    if csv_path:
        msg += f"  matrix:      {csv_path}\n"
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
