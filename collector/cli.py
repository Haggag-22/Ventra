"""Ventra command-line interface.

    ventra collect aws --case CASE-2026-0042 \
        --since 2026-05-11 --regions us-east-1,us-west-2 --out ./ventra-evidence

By default the sealed package is ingested into ./cases (or $VENTRA_CASE_STORE) so the
console can open the case immediately. Use ``--no-ingest`` for package-only acquisition
(e.g. AWS CloudShell before handoff to the IR workstation).

    ventra dev     # local console with hot reload (development)
    ventra gui     # production console (Docker Compose or --local build)

``ventra-collect aws …`` is accepted as shorthand for the same collect command.

Runs every registered collector for the cloud. The CLI is deliberately thin: it parses
arguments, builds an AwsRunConfig, and delegates to the runner.

While a collection runs, the CLI renders a live "collection matrix" — one PASS or FAIL row
per source as it completes — so the operator can see exactly what was captured and what was
missing (a gap is evidence). The same matrix is written to ``collection_matrix.csv`` in the
output directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .lib.models import SourceStatus, utcnow_iso
from .lib.transport import get_transport


def _add_aws_parser(sub: argparse._SubParsersAction) -> None:
    aws = sub.add_parser("aws", help="Collect from AWS (the first supported cloud).")
    aws.add_argument("--case", help="Case identifier, e.g. CASE-2026-0042.")
    aws.add_argument("--engagement", default="", help="Optional engagement/matter id.")
    aws.add_argument("--regions", default="", help="Comma-separated regions (default: all enabled).")
    aws.add_argument("--since", default=None, help="Window start (YYYY-MM-DD or RFC3339 UTC).")
    aws.add_argument("--until", default=None, help="Window end (YYYY-MM-DD or RFC3339 UTC).")
    aws.add_argument("--out", default="./ventra-evidence", help="Output directory for the package.")
    aws.add_argument("--transport", default="local", help="local | s3-presigned:<url> | sftp:...")
    aws.add_argument("--key", default=None, help="Signing key path for cosign/minisign.")
    aws.add_argument(
        "--case-store",
        default=None,
        help="Case store for auto-ingest after collect (default: $VENTRA_CASE_STORE or ./cases).",
    )
    aws.add_argument(
        "--no-ingest",
        action="store_true",
        help="Seal the package only; do not load into the case store.",
    )
    aws.add_argument("--list-collectors", action="store_true", help="List collectors and exit.")


def build_parser(*, prog: str = "ventra") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Ventra — cloud forensic triage: collect, develop, and investigate.",
    )
    p.add_argument("--version", action="version", version=f"ventra {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="Collect forensic evidence from a cloud.")
    clouds = collect.add_subparsers(dest="cloud", required=True)
    _add_aws_parser(clouds)

    dev = sub.add_parser(
        "dev",
        help="Run the analyst console locally with hot reload (development).",
    )
    dev.add_argument("--port", type=int, default=8080, help="Frontend port (default: 8080).")
    dev.add_argument(
        "--backend-port", type=int, default=8000, help="Backend port (default: 8000)."
    )
    dev.add_argument("--no-open", action="store_true", help="Do not open a browser tab.")
    dev.add_argument(
        "--setup",
        action="store_true",
        help="Re-run pip/npm install even if dependencies look current.",
    )

    gui = sub.add_parser(
        "gui",
        help="Run the production analyst console (Docker Compose or local build).",
    )
    gui.add_argument(
        "--local",
        action="store_true",
        help="Build and run locally instead of Docker Compose.",
    )
    gui.add_argument(
        "--rebuild",
        action="store_true",
        help="With --local, force a fresh frontend build.",
    )
    gui.add_argument("--port", type=int, default=8080, help="Frontend port (default: 8080).")
    gui.add_argument(
        "--backend-port", type=int, default=8000, help="Backend port (default: 8000)."
    )
    gui.add_argument("--no-open", action="store_true", help="Do not open a browser tab.")
    gui.add_argument(
        "--setup",
        action="store_true",
        help="Re-run pip/npm install even if dependencies look current.",
    )
    return p


def _normalize_argv(argv: list[str]) -> list[str]:
    """Accept legacy ``ventra aws …`` and ``ventra-collect aws …`` invocations."""
    if not argv:
        return argv
    if argv[0] in ("collect", "dev", "gui"):
        return argv
    if argv[0] == "aws":
        return ["collect", *argv]
    return ["collect", *argv]


# Per-source severity. Drives the PASS/FAIL/INFO classification: a *missing* High source
# (service not enabled / logging not configured) is a FAIL; a missing Medium/Low source is
# informational. This mirrors how a responder weighs a coverage gap.
_SEVERITY: dict[str, str] = {
    "account": "Low",
    "cloudtrail": "High",
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
    "inspector2": "Medium",
    "elb_alb": "Medium",
    "cloudfront": "Medium",
    "s3_access": "Medium",
    "route53_resolver": "Medium",
    "eks_audit": "Medium",
    "log_posture": "Low",
}

_SEV_COLOR = {"High": "red", "Medium": "yellow", "Low": "cyan"}


def _classify(status: SourceStatus, severity: str) -> tuple[str, str]:
    """Map a collector outcome to PASS or FAIL for the live matrix."""
    del severity  # binary matrix; severity stays in CSV detail only
    if status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL):
        return "PASS", "green"
    return "FAIL", "red"


def _cli_reporter():
    """Build the live-matrix reporter. Returns (reporter, console_or_None)."""
    from .aws.registry import AWS_REGISTRY
    from .aws.runner.runner import RunReporter

    try:
        from rich.box import ROUNDED
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table

        console = Console()
    except Exception:  # pragma: no cover - rich is a declared dependency
        console = None
        Live = None  # type: ignore[misc, assignment]
        Table = None  # type: ignore[misc, assignment]
        ROUNDED = None  # type: ignore[misc, assignment]

    class MatrixReporter(RunReporter):
        """Streams one matrix row per source as it completes, with a live table."""

        def __init__(self) -> None:
            super().__init__()
            self.rows: list[dict] = []
            self._console = console
            self._live = None
            self._table = None
            self._plain_header = False
            self._account = ""
            self._masked = "????"

        def _new_table(self):
            table = Table(
                show_header=True,
                header_style="bold bright_black",
                box=ROUNDED,
                expand=True,
                pad_edge=False,
            )
            table.add_column("Status", width=6, no_wrap=True)
            table.add_column("Collector", width=14, no_wrap=True)
            table.add_column("Severity", width=8, no_wrap=True)
            table.add_column("Records", width=10, justify="right", no_wrap=True)
            table.add_column("Detail", ratio=1, overflow="ellipsis", no_wrap=True)
            return table

        # -- lifecycle ------------------------------------------------------
        def begin_run(self, account_id: str, regions: list[str], case_id: str = "") -> None:
            self._account = account_id or ""
            self._masked = (account_id[:4] + "***") if account_id else "????"
            ts = utcnow_iso()
            if self._console:
                self._console.print()
                self._console.rule("[bold]Ventra[/bold] · Live Collection Matrix")
                self._console.print(f"Account ID : [bold]{self._masked}[/bold]")
                if case_id:
                    self._console.print(f"Case       : {case_id}")
                self._console.print(f"Scope      : Global / {len(regions)} region(s)")
                self._console.print(f"Timestamp  : {ts}")
                self._console.print()
                self._table = self._new_table()
                self._live = Live(self._table, console=self._console, refresh_per_second=8)
                self._live.start()
            else:
                print(f"[+] Ventra collection — account {self._masked} — {ts}")

        def start(self, name: str) -> None:
            if self._table is not None and self._live is not None:
                self._table.caption = f"Collecting [yellow]{name}[/]…"
                self._live.update(self._table)

        def finish(self, name: str, result) -> None:
            row = self._build_row(name, result)
            self.rows.append(row)
            self._append_row(row)

        def stop(self) -> None:
            if self._live is not None:
                self._live.stop()
                self._live = None

        def finalize(self) -> None:
            if self._table is not None and self._live is not None:
                self._table.caption = None
                self._live.update(self._table)
            self.stop()
            from collections import Counter

            c = Counter(r["label"] for r in self.rows)
            if self._console:
                self._console.print(
                    f"\n[+] Collection complete: "
                    f"[green]{c.get('PASS', 0)} pass[/green], "
                    f"[red]{c.get('FAIL', 0)} fail[/red]"
                )
            else:
                print(
                    f"[+] Complete: {c.get('PASS', 0)} pass, {c.get('FAIL', 0)} fail"
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

        def _append_row(self, row: dict) -> None:
            if self._table is not None and self._live is not None:
                self._table.add_row(
                    f"[bold {row['color']}]{row['label']}[/]",
                    row["check"],
                    f"[{row['sev_color']}]{row['severity']}[/]",
                    row["tag"],
                    row["desc"],
                )
                self._table.caption = None
                self._live.update(self._table)
                return

            if not self._plain_header:
                print(f"{'STATUS':<6} {'COLLECTOR':<14} {'SEVERITY':<8} {'RECORDS':>10}  DETAIL")
                print("─" * 80)
                self._plain_header = True
            print(
                f"{row['label']:<6} {row['check']:<14} {row['severity']:<8} "
                f"{row['tag']:>10}  {row['desc']}"
            )

        # -- row construction ----------------------------------------------
        def _build_row(self, name: str, result) -> dict:
            cls = AWS_REGISTRY.get(name)
            priority = getattr(cls, "priority", 2)
            severity = _SEVERITY.get(name, "High" if priority == 1 else "Medium")
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

    return MatrixReporter(), console


def main(argv: list[str] | None = None) -> int:
    argv = _normalize_argv(list(argv if argv is not None else sys.argv[1:]))
    args = build_parser().parse_args(argv)

    if args.command == "dev":
        from .devgui import cmd_dev

        return cmd_dev(args)
    if args.command == "gui":
        from .devgui import cmd_gui

        return cmd_gui(args)
    if args.command != "collect":
        print(f"Unknown command {args.command!r}.", file=sys.stderr)
        return 2
    if args.cloud == "aws":
        return _run_aws(args)
    print(f"Cloud {args.cloud!r} is scaffolded but not yet implemented.", file=sys.stderr)
    return 2


def main_legacy(argv: list[str] | None = None) -> int:
    """Entry point for the ``ventra-collect`` console script."""
    return main(_normalize_argv(list(argv if argv is not None else sys.argv[1:])))


def _run_aws(args) -> int:
    from .aws.registry import AWS_REGISTRY, all_collector_names
    from .aws.runner.runner import AwsRunConfig, parse_window, run_aws_collection

    if args.list_collectors:
        for name, cls in sorted(AWS_REGISTRY.all().items()):
            print(f"  {name:<14} {cls.description}")
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

    if args.no_ingest:
        return 0

    from .lib.ingest import default_case_store, ingest_after_collect

    case_store = Path(args.case_store) if args.case_store else default_case_store()
    say = console.print if console else print
    return ingest_after_collect(package.path, case_store, reporter=say)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
