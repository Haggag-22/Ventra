"""Ventra command-line interface.

    ventra collect aws --case CASE-2026-0042 \
        --since 2026-05-11 --regions us-east-1,us-west-2 --out ./ventra-evidence

On an IR workstation the sealed package is ingested into ./cases (or $VENTRA_CASE_STORE) so
the console can open the case immediately. In AWS CloudShell — acquisition-only, before
handoff to the IR workstation — ingest is skipped automatically; pass ``--ingest`` to force
it, or ``--no-ingest`` to skip it anywhere.

    ventra gui     # open the analyst console GUI locally (hot reload; no Docker)

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
import time
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
    aws.add_argument(
        "--ingest",
        action="store_true",
        help="Force auto-ingest into the case store, even in CloudShell.",
    )
    aws.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the live matrix; print only the final summary.",
    )
    aws.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit a machine-readable JSON summary to stdout (implies no live matrix).",
    )
    aws.add_argument("--list-collectors", action="store_true", help="List collectors and exit.")


def _add_azure_parser(sub: argparse._SubParsersAction) -> None:
    az = sub.add_parser("azure", help="Collect from Azure.")
    az.add_argument("--case", help="Case identifier, e.g. CASE-2026-0042.")
    az.add_argument("--engagement", default="", help="Optional engagement/matter id.")
    az.add_argument(
        "--subscription",
        default="",
        help="Azure subscription id (default: AZURE_SUBSCRIPTION_ID env).",
    )
    az.add_argument("--regions", default="", help="Comma-separated regions (default: all enabled).")
    az.add_argument("--since", default=None, help="Window start (YYYY-MM-DD or RFC3339 UTC).")
    az.add_argument("--until", default=None, help="Window end (YYYY-MM-DD or RFC3339 UTC).")
    az.add_argument("--out", default="./ventra-evidence", help="Output directory for the package.")
    az.add_argument("--transport", default="local", help="local | s3-presigned:<url> | sftp:...")
    az.add_argument("--key", default=None, help="Signing key path for cosign/minisign.")
    az.add_argument(
        "--case-store",
        default=None,
        help="Case store for auto-ingest after collect (default: $VENTRA_CASE_STORE or ./cases).",
    )
    az.add_argument(
        "--no-ingest",
        action="store_true",
        help="Seal the package only; do not load into the case store.",
    )
    az.add_argument(
        "--ingest",
        action="store_true",
        help="Force auto-ingest into the case store.",
    )
    az.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the live matrix; print only the final summary.",
    )
    az.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit a machine-readable JSON summary to stdout (implies no live matrix).",
    )
    az.add_argument("--list-collectors", action="store_true", help="List collectors and exit.")


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
    _add_azure_parser(clouds)

    def _add_gui_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--port", type=int, default=8080, help="Frontend port (default: 8080).")
        parser.add_argument(
            "--backend-port", type=int, default=8000, help="Backend port (default: 8000)."
        )
        parser.add_argument("--no-open", action="store_true", help="Do not open a browser tab.")
        parser.add_argument(
            "--setup",
            action="store_true",
            help="Re-run pip/npm install even if dependencies look current.",
        )

    gui = sub.add_parser(
        "gui",
        help="Open the Ventra console GUI locally (hot reload). No Docker.",
    )
    _add_gui_args(gui)

    # ``dev`` is kept as an alias of ``gui`` so older muscle memory and `make dev` keep working.
    dev = sub.add_parser("dev", help="Alias of `gui`.")
    _add_gui_args(dev)
    return p


def _should_auto_ingest(args: argparse.Namespace) -> bool:
    """Decide whether to load the sealed package into the case store after collect.

    Explicit flags win; otherwise auto-ingest everywhere except CloudShell, which is
    acquisition-only (the case store and console live on the IR workstation).
    """
    from .lib.ingest import running_in_cloudshell

    if getattr(args, "no_ingest", False):
        return False
    if getattr(args, "ingest", False):
        return True
    return not running_in_cloudshell()


def _normalize_argv(argv: list[str]) -> list[str]:
    """Accept legacy ``ventra aws …`` and ``ventra-collect aws …`` invocations."""
    if not argv:
        return argv
    # Top-level flags must not be rewritten to ``collect --version`` etc.
    if argv[0] in ("--version", "-V", "-h", "--help"):
        return argv
    if argv[0] in ("collect", "dev", "gui"):
        return argv
    if argv[0] == "aws":
        return ["collect", *argv]
    if argv[0] == "azure":
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
    "subscription": "Low",
    "activity_log": "High",
    "entra_signin": "High",
    "entra_audit": "High",
    "rbac": "High",
    "nsg_flow": "High",
    "defender": "High",
}

_SEV_COLOR = {"High": "red", "Medium": "yellow", "Low": "cyan"}


def _classify(status: SourceStatus, severity: str) -> tuple[str, str]:
    """Map a collector outcome to PASS or FAIL for the live matrix."""
    del severity  # binary matrix; severity stays in CSV detail only
    if status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL):
        return "PASS", "green"
    return "FAIL", "red"


def _fmt_dur(seconds: float | None) -> str:
    """Compact human duration: ``2.3s``, ``47s``, ``1m05s``."""
    if seconds is None:
        return ""
    if seconds < 10:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s"


def _cli_reporter(*, quiet: bool = False, json_mode: bool = False, cloud: str = "aws"):
    """Build the live-matrix reporter. Returns (reporter, console_or_None)."""
    if cloud == "azure":
        from .azure.registry import AZURE_REGISTRY as REGISTRY

        cloud_title = "Azure"
    else:
        from .aws.registry import AWS_REGISTRY as REGISTRY

        cloud_title = "AWS"
    from .aws.runner.runner import RunReporter

    try:
        from rich.box import ROUNDED
        from rich.console import Console
        from rich.live import Live
        from rich.markup import escape
        from rich.spinner import Spinner
        from rich.table import Table

        console = Console()
    except Exception:  # pragma: no cover - rich is a declared dependency
        console = None
        Live = None  # type: ignore[misc, assignment]
        Table = None  # type: ignore[misc, assignment]
        Spinner = None  # type: ignore[misc, assignment]
        ROUNDED = None  # type: ignore[misc, assignment]
        escape = str  # type: ignore[assignment]

    # Per-status glyph for the Status column.
    _PENDING = "[dim]○[/dim]"
    _PASS = "[bold green]✓[/]"
    _FAIL = "[bold red]✗[/]"

    class MatrixReporter(RunReporter):
        """A single live table: one pre-populated row per collector, updated in place."""

        def __init__(self) -> None:
            super().__init__()
            self.rows: list[dict] = []  # finished rows, for the CSV export
            self._console = console
            self._quiet = quiet
            self._json = json_mode
            self._silent = quiet or json_mode  # no live matrix in either mode
            self._live = None
            self._spinner = None
            self._plain_header = False
            self._account = ""
            self._masked = "????"
            # Ordered list of collector names and their mutable display state.
            self._order: list[str] = []
            self._state: dict[str, dict] = {}

        def _new_table(self):
            table = Table(
                show_header=True,
                header_style="bold bright_black",
                box=ROUNDED,
                expand=True,
                pad_edge=False,
            )
            table.add_column("", width=3, no_wrap=True, justify="center")  # status glyph
            table.add_column("Collector", width=16, no_wrap=True)
            table.add_column("Severity", width=8, no_wrap=True)
            table.add_column("Records", width=10, justify="right", no_wrap=True)
            table.add_column("Time", width=7, justify="right", no_wrap=True)
            table.add_column("Detail", ratio=1, overflow="ellipsis", no_wrap=True)
            return table

        def _severity_for(self, name: str) -> str:
            cls = REGISTRY.get(name)
            priority = getattr(cls, "priority", 2)
            return _SEVERITY.get(name, "High" if priority == 1 else "Medium")

        # -- lifecycle ------------------------------------------------------
        def begin_run(
            self,
            account_id: str,
            regions: list[str],
            case_id: str = "",
            collectors: list[str] | None = None,
        ) -> None:
            self._account = account_id or ""
            self._masked = (account_id[:4] + "***") if account_id else "????"
            self._order = list(collectors or [])
            for name in self._order:
                self._state[name] = {
                    "status": "pending",
                    "count": None,
                    "detail": "queued",
                    "severity": self._severity_for(name),
                    "elapsed": None,
                    "started": None,
                    "live_msg": "",
                }

            region_str = (
                ", ".join(regions) if regions and len(regions) <= 6
                else f"{len(regions)} region(s)"
            )
            ts = utcnow_iso()

            if self._json:
                return
            if self._quiet:
                print(
                    f"[+] Ventra collection — account {self._masked} — case {case_id or '—'} "
                    f"— {region_str} — {len(self._order)} collectors"
                )
                return

            if self._console:
                self._spinner = Spinner("dots", style="yellow")
                self._console.print()
                self._console.rule(f"[bold cyan]VENTRA[/]  ·  {cloud_title} Evidence Collection")
                self._console.print(
                    f"  [bright_black]Account[/] [bold]{self._masked}[/]"
                    f"   [bright_black]Case[/] [bold]{escape(case_id or '—')}[/]"
                    f"   [bright_black]Regions[/] [bold]{escape(region_str)}[/]"
                    f"   [bright_black]Started[/] [bold]{ts}[/]"
                )
                self._console.print()
                self._live = Live(
                    self._render_table(),
                    console=self._console,
                    refresh_per_second=12,
                    transient=False,
                )
                self._live.start()
            else:
                print(f"[+] Ventra collection — account {self._masked} — {ts}")
                print(f"    case {case_id or '—'} · {region_str} · {len(self._order)} collectors")

        def _render_table(self):
            table = self._new_table()
            done = 0
            for name in self._order:
                st = self._state[name]
                status = st["status"]
                if status == "pending":
                    glyph = _PENDING
                    detail = "[dim]queued[/dim]"
                    records = "[dim]-[/dim]"
                    time_cell = ""
                elif status == "running":
                    glyph = self._spinner
                    msg = st["live_msg"] or "collecting…"
                    detail = f"[yellow]{escape(msg)}[/yellow]"
                    records = "[dim]·[/dim]"
                    started = st["started"]
                    live = _fmt_dur(time.monotonic() - started) if started else ""
                    time_cell = f"[dim]{live}[/dim]"
                else:
                    done += 1
                    glyph = _PASS if status == "pass" else _FAIL
                    detail = escape(st["detail"] or "")
                    records = (
                        f"{st['count']:,}" if isinstance(st["count"], int) else "[dim]-[/dim]"
                    )
                    time_cell = f"[bright_black]{_fmt_dur(st['elapsed'])}[/]"
                sev = st["severity"]
                sev_cell = f"[{_SEV_COLOR.get(sev, 'white')}]{sev}[/]"
                name_cell = (
                    f"[dim]{name.upper()}[/dim]" if status == "pending" else name.upper()
                )
                table.add_row(glyph, name_cell, sev_cell, records, time_cell, detail)
            total = len(self._order)
            table.caption = f"[bright_black]{done}/{total} collectors complete[/]"
            return table

        def _refresh(self) -> None:
            if self._live is not None:
                self._live.update(self._render_table())

        def start(self, name: str) -> None:
            if name in self._state:
                self._state[name]["status"] = "running"
                self._state[name]["started"] = time.monotonic()
            if not self._silent:
                self._refresh()

        def event(self, name: str, msg: str) -> None:
            """Surface a collector's latest sub-step in its (running) row."""
            super().event(name, msg)
            st = self._state.get(name)
            if st is not None and st["status"] == "running":
                st["live_msg"] = msg
                if not self._silent:
                    self._refresh()

        def finish(self, name: str, result) -> None:
            severity = self._state.get(name, {}).get("severity") or self._severity_for(name)
            label, _ = _classify(result.status, severity)
            count = result.record_count
            tag = f"{count:,}" if isinstance(count, int) else "-"
            if result.status != SourceStatus.COLLECTED and result.gaps:
                desc = result.gaps[0][2] or result.notes
            else:
                cls = REGISTRY.get(name)
                desc = result.notes or (cls.description if cls else "")

            elapsed = None
            if name in self._state:
                started = self._state[name]["started"]
                elapsed = (time.monotonic() - started) if started else None
                self._state[name].update(
                    status="pass" if label == "PASS" else "fail",
                    count=count if isinstance(count, int) else None,
                    detail=desc,
                    elapsed=elapsed,
                    live_msg="",
                )
            self.rows.append(
                {
                    "label": label,
                    "scope": "global",
                    "check": name.upper(),
                    "severity": severity,
                    "tag": tag,
                    "elapsed": f"{elapsed:.2f}" if elapsed is not None else "",
                    "desc": desc,
                }
            )

            if self._silent:
                return
            if self._live is not None:
                self._refresh()
            elif self._console is None:
                self._print_plain_row(label, name, severity, tag, _fmt_dur(elapsed), desc)

        def stop(self) -> None:
            if self._live is not None:
                self._live.stop()
                self._live = None

        def finalize(self) -> None:
            if not self._silent:
                self._refresh()
            self.stop()
            if self._json:
                return  # the CLI emits the JSON document instead
            self._emit_summary()

        # -- summaries / structured output ---------------------------------
        def coverage_gaps(self) -> list[dict]:
            """Collectors that did not collect, worst severity first — these are the gaps."""
            rank = {"High": 0, "Medium": 1, "Low": 2}
            gaps = [
                {
                    "collector": name,
                    "severity": st["severity"],
                    "detail": st["detail"],
                }
                for name in self._order
                for st in (self._state[name],)
                if st["status"] == "fail"
            ]
            gaps.sort(key=lambda g: rank.get(g["severity"], 3))
            return gaps

        def collectors_report(self) -> list[dict]:
            """Per-collector structured result for the --json payload."""
            return [
                {
                    "name": name,
                    "status": self._state[name]["status"],
                    "severity": self._state[name]["severity"],
                    "records": self._state[name]["count"],
                    "elapsed_seconds": (
                        round(self._state[name]["elapsed"], 3)
                        if self._state[name]["elapsed"] is not None
                        else None
                    ),
                    "detail": self._state[name]["detail"],
                }
                for name in self._order
            ]

        def _emit_summary(self) -> None:
            from collections import Counter

            c = Counter(r["label"] for r in self.rows)
            passed, failed = c.get("PASS", 0), c.get("FAIL", 0)
            gaps = self.coverage_gaps()
            if self._console:
                self._console.print(
                    f"\n  [bold green]✓ {passed} passed[/]   "
                    f"[bold red]✗ {failed} failed[/]   "
                    f"[bright_black]{len(self.rows)} collectors[/]"
                )
                if gaps:
                    self._console.print(
                        "\n  [bold]Coverage gaps[/] "
                        "[bright_black](sources not collected — a gap is evidence)[/]"
                    )
                    for g in gaps:
                        col = _SEV_COLOR.get(g["severity"], "white")
                        self._console.print(
                            f"    [{col}]✗ {g['severity']:<6}[/] "
                            f"[bold]{g['collector'].upper():<16}[/] "
                            f"[bright_black]{escape(g['detail'] or '')}[/]"
                        )
            else:
                print(f"[+] Complete: {passed} pass, {failed} fail")
                for g in gaps:
                    print(
                        f"    GAP {g['severity']:<6} {g['collector'].upper():<16} "
                        f"{g['detail'] or ''}"
                    )

        def write_matrix_csv(self, out_dir) -> Path:
            import csv

            out = Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            path = out / "collection_matrix.csv"
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(
                    ["status", "account", "scope", "check", "severity", "records",
                     "elapsed_s", "detail"]
                )
                for r in self.rows:
                    w.writerow(
                        [r["label"], self._account, r["scope"], r["check"],
                         r["severity"], r["tag"], r["elapsed"], r["desc"]]
                    )
            return path

        def _print_plain_row(
            self, label: str, name: str, severity: str, records: str, elapsed: str, detail: str
        ) -> None:
            if not self._plain_header:
                print(
                    f"{'STATUS':<6} {'COLLECTOR':<16} {'SEVERITY':<8} {'RECORDS':>10} "
                    f"{'TIME':>7}  DETAIL"
                )
                print("─" * 88)
                self._plain_header = True
            print(
                f"{label:<6} {name.upper():<16} {severity:<8} {records:>10} "
                f"{elapsed:>7}  {detail}"
            )

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
    if args.cloud == "azure":
        return _run_azure(args)
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

    json_mode = args.json_output
    reporter, console = _cli_reporter(quiet=args.quiet, json_mode=json_mode, cloud="aws")

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
        if json_mode:
            import json as _json

            print(_json.dumps({"case_id": args.case, "error": str(exc)}, indent=2))
        else:
            print(f"\nCollection failed: {exc}", file=sys.stderr)
        return 1

    reporter.finalize()
    try:
        csv_path = reporter.write_matrix_csv(args.out)
    except Exception:  # noqa: BLE001 - matrix is a convenience artifact, never fatal
        csv_path = None

    if not json_mode:
        msg = (
            f"\nSealed package: {package.path}\n"
            f"  compression: {package.compression}\n"
            f"  size:        {package.bytes:,} bytes\n"
            f"  sha256:      {package.sha256}\n"
        )
        if csv_path:
            msg += f"  matrix:      {csv_path}\n"
        (console.print if console else print)(msg)

    # Deliver via the chosen transport.
    transport_location: str | None = None
    transport_error: str | None = None
    try:
        transport_location = get_transport(args.transport).deliver(package.path)
        if not json_mode:
            print(f"Delivered: {transport_location}")
    except Exception as exc:  # noqa: BLE001
        transport_error = str(exc)
        if not json_mode:
            print(f"Transport failed ({args.transport}): {exc}", file=sys.stderr)
            print(f"Package remains at {package.path}", file=sys.stderr)

    # Auto-ingest only when applicable (skipped in CloudShell), and only if delivered.
    ingested: bool | None = None
    ingest_code = 0
    if transport_error is None and _should_auto_ingest(args):
        from .lib.ingest import default_case_store, ingest_after_collect

        case_store = Path(args.case_store) if args.case_store else default_case_store()
        if json_mode:
            ingest_code = ingest_after_collect(package.path, case_store, reporter=lambda _m: None)
        else:
            say = console.print if console else print
            ingest_code = ingest_after_collect(package.path, case_store, reporter=say)
        ingested = ingest_code == 0

    if json_mode:
        import json as _json

        payload = {
            "case_id": args.case,
            "engagement_id": args.engagement or None,
            "account_id": reporter._account,
            "collectors": reporter.collectors_report(),
            "coverage_gaps": reporter.coverage_gaps(),
            "package": {
                "path": str(package.path),
                "compression": package.compression,
                "bytes": package.bytes,
                "sha256": package.sha256,
            },
            "matrix_csv": str(csv_path) if csv_path else None,
            "transport": {
                "target": args.transport,
                "location": transport_location,
                "error": transport_error,
            },
            "ingested": ingested,
        }
        print(_json.dumps(payload, indent=2))

    return 1 if transport_error else ingest_code


def _run_azure(args) -> int:
    from .azure.registry import AZURE_REGISTRY, all_collector_names
    from .azure.runner.runner import AzureRunConfig, parse_window, run_azure_collection

    if args.list_collectors:
        for name, cls in sorted(AZURE_REGISTRY.all().items()):
            print(f"  {name:<16} {cls.description}")
        return 0

    if not args.case:
        print("error: --case is required to run a collection.", file=sys.stderr)
        return 2

    collectors = all_collector_names()
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] or None
    window = parse_window(args.since, args.until)
    subscription = args.subscription.strip() or None

    json_mode = args.json_output
    reporter, console = _cli_reporter(quiet=args.quiet, json_mode=json_mode, cloud="azure")

    cfg = AzureRunConfig(
        case_id=args.case,
        collectors=collectors,
        regions=regions,
        subscription_id=subscription,
        time_window=window,
        out_dir=Path(args.out),
        engagement_id=args.engagement,
        key_path=Path(args.key) if args.key else None,
        reporter=reporter,
    )

    try:
        package = run_azure_collection(cfg)
    except Exception as exc:  # noqa: BLE001
        reporter.stop()
        if json_mode:
            import json as _json

            print(_json.dumps({"case_id": args.case, "error": str(exc)}, indent=2))
        else:
            print(f"\nCollection failed: {exc}", file=sys.stderr)
        return 1

    reporter.finalize()
    try:
        csv_path = reporter.write_matrix_csv(args.out)
    except Exception:  # noqa: BLE001
        csv_path = None

    if not json_mode:
        msg = (
            f"\nSealed package: {package.path}\n"
            f"  compression: {package.compression}\n"
            f"  size:        {package.bytes:,} bytes\n"
            f"  sha256:      {package.sha256}\n"
        )
        if csv_path:
            msg += f"  matrix:      {csv_path}\n"
        (console.print if console else print)(msg)

    transport_location: str | None = None
    transport_error: str | None = None
    try:
        transport_location = get_transport(args.transport).deliver(package.path)
        if not json_mode:
            print(f"Delivered: {transport_location}")
    except Exception as exc:  # noqa: BLE001
        transport_error = str(exc)
        if not json_mode:
            print(f"Transport failed ({args.transport}): {exc}", file=sys.stderr)
            print(f"Package remains at {package.path}", file=sys.stderr)

    ingested: bool | None = None
    ingest_code = 0
    if transport_error is None and _should_auto_ingest(args):
        from .lib.ingest import default_case_store, ingest_after_collect

        case_store = Path(args.case_store) if args.case_store else default_case_store()
        if json_mode:
            ingest_code = ingest_after_collect(package.path, case_store, reporter=lambda _m: None)
        else:
            say = console.print if console else print
            ingest_code = ingest_after_collect(package.path, case_store, reporter=say)
        ingested = ingest_code == 0

    if json_mode:
        import json as _json

        payload = {
            "case_id": args.case,
            "engagement_id": args.engagement or None,
            "account_id": reporter._account,
            "collectors": reporter.collectors_report(),
            "coverage_gaps": reporter.coverage_gaps(),
            "package": {
                "path": str(package.path),
                "compression": package.compression,
                "bytes": package.bytes,
                "sha256": package.sha256,
            },
            "matrix_csv": str(csv_path) if csv_path else None,
            "transport": {
                "target": args.transport,
                "location": transport_location,
                "error": transport_error,
            },
            "ingested": ingested,
        }
        print(_json.dumps(payload, indent=2))

    return 1 if transport_error else ingest_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
