"""Terminal output for ``ventra run``: a short header, one row per collector, a short summary.

Raw errors never reach the terminal; they go to the run log (:data:`RUN_LOG_NAME`) in the
output folder, and the summary points at it in one line.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table

from collector.engine.matrix_state import CollectorRow, MatrixState
from collector.engine.run_common import RunReporter

from .format import human_duration, short_remaining, utcnow

if TYPE_CHECKING:
    from .format import KitManifest

RUN_LOG_NAME = "ventra-run.log"

CLOUD_TITLES = {"aws": "AWS", "gcp": "GCP", "azure": "Azure", "kubernetes": "Kubernetes"}

_STATUS_TEXT = {"pending": "Pending", "running": "Running", "pass": "Succeeded", "fail": "Failed"}
_STATUS_STYLE = {"pending": "dim", "running": "yellow", "pass": "green", "fail": "red"}


def cloud_title(cloud: str) -> str:
    return CLOUD_TITLES.get(cloud, cloud.upper() or "?")


def status_text(status: str) -> str:
    return _STATUS_TEXT.get(status, status.title())


def records_text(row: CollectorRow) -> str:
    if row.status == "fail":
        return "-"
    if isinstance(row.records, int):
        return f"{row.records:,}"
    return "0" if row.status == "pass" else ""


def make_console() -> Console:
    return Console(highlight=False)


def build_table(matrix: MatrixState) -> Table:
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, show_edge=False)
    table.add_column("Collector", no_wrap=True, overflow="ellipsis", max_width=32)
    table.add_column("Records", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True, min_width=10)
    for name in matrix.order:
        row = matrix.rows[name]
        style = _STATUS_STYLE.get(row.status, "")
        name_cell = f"[dim]{escape(name)}[/dim]" if row.status == "pending" else escape(name)
        status = f"[{style}]{status_text(row.status)}[/]" if style else status_text(row.status)
        table.add_row(name_cell, records_text(row), status)
    return table


def expiry_lines(manifest: KitManifest, *, now: datetime | None = None) -> list[str]:
    """The ``Expires`` value, plus a second line when the credential (not the kit) is the limit."""
    now = now or utcnow()
    exp = manifest.effective_expiry()
    left = short_remaining((exp - now).total_seconds())
    upper_bound = bool(manifest.credential and manifest.credential.details.get("expiry_is_upper_bound"))
    first = f"{exp:%Y-%m-%d %H:%M} UTC{' at the latest' if upper_bound else ''} (in {left})"
    ttl = manifest.kit_ttl_seconds
    allows = f"; the kit itself allows {human_duration(ttl)}" if ttl else ""
    cloud = cloud_title(manifest.cloud)
    if manifest.limited_by == "credential":
        return [first, f"Set by the {cloud} credential's lifetime{allows}."]
    if manifest.limited_by == "static_secret":
        return [first, f"Kept short because this kit carries a long-lived {cloud} secret."]
    return [first]


def print_header(
    console: Console,
    manifest: KitManifest,
    *,
    out_dir: Path,
    deliver_to: str = "",
) -> None:
    title = manifest.kit_name or manifest.case_id
    console.print()
    console.print(f"[bold]Ventra[/bold] · {escape(title)}")
    rows: list[tuple[str, str]] = [
        ("Case", manifest.case_id or "-"),
        ("Cloud", cloud_title(manifest.cloud)),
        ("Output", str(out_dir)),
    ]
    exp = expiry_lines(manifest)
    rows.append(("Expires", exp[0]))
    rows.extend(("", line) for line in exp[1:])
    if deliver_to:
        rows.append(("Deliver", deliver_to))
    for label, value in rows:
        _print_field(console, label, escape(value))
    console.print()


def summary_counts(rows: list[dict[str, Any]]) -> tuple[int, int, int]:
    succeeded = sum(1 for r in rows if r.get("status") == "pass")
    failed = sum(1 for r in rows if r.get("status") == "fail")
    records = sum(r["records"] for r in rows if isinstance(r.get("records"), int))
    return succeeded, failed, records


def print_summary(
    console: Console,
    *,
    success: bool,
    rows: list[dict[str, Any]],
    package_path: Path | None,
    error: str = "",
    delivered_to: str = "",
    delivery_failed: bool = False,
    log_path: Path | None = None,
) -> None:
    console.print()
    if not success:
        console.print(f"[bold red]Run failed.[/] {escape(error)}".rstrip())
    else:
        succeeded, failed, records = summary_counts(rows)
        parts = [f"{succeeded} succeeded"]
        if failed:
            parts.append(f"[red]{failed} failed[/red]")
        heading = "[bold green]Done.[/]" if not failed else "[bold yellow]Done.[/]"
        console.print(f"{heading} {', '.join(parts)} · {records:,} records")
    if package_path:
        _print_field(console, "Evidence", escape(str(package_path)))
    if delivered_to:
        _print_field(console, "Uploaded", escape(delivered_to))
    elif delivery_failed:
        _print_field(console, "Upload", "[red]failed[/red]; the evidence above is intact")
    if log_path is not None:
        _print_field(console, "Details", escape(str(log_path)))
    console.print()


def _print_field(console: Console, label: str, value: str) -> None:
    # Long paths flow onto the next line instead of being pushed below the label.
    console.print(f"  [dim]{label:<9}[/dim] {value}", soft_wrap=True)


class KitRunView(RunReporter):
    """Live collector table for ``ventra run`` (plain rows when stdout is not a terminal)."""

    def __init__(self, console: Console | None = None) -> None:
        super().__init__()
        self.console = console or make_console()
        self.matrix = MatrixState()
        self._live: Any = None
        self._plain_header = False

    def begin_run(
        self,
        account_id: str,
        regions: list[str],
        case_id: str = "",
        collectors: list[str] | None = None,
        **_: Any,
    ) -> None:
        self.matrix.begin_run(account_id, regions, case_id, collectors)
        if self.console.is_terminal:
            from rich.live import Live

            self._live = Live(self._render(), console=self.console, refresh_per_second=8, transient=False)
            self._live.start()

    def _render(self) -> Padding:
        return Padding(build_table(self.matrix), (0, 0, 0, 2), expand=False)

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._render())

    def start(self, name: str) -> None:
        self.matrix.start(name)
        self._refresh()

    def event(self, name: str, msg: str, records: int | None = None) -> None:
        super().event(name, msg, records=records)
        self.matrix.event(name, msg, records=records)
        self._refresh()

    def finish(self, name: str, result: Any) -> None:
        self.matrix.finish(name, result)
        if self._live is not None:
            self._refresh()
            return
        row = self.matrix.rows.get(name)
        if row is not None:
            self._print_plain_row(row)

    def _print_plain_row(self, row: CollectorRow) -> None:
        width = max([len(n) for n in self.matrix.order] + [len("Collector")])
        if not self._plain_header:
            self.console.print(f"  {'Collector':<{width}}  {'Records':>10}  Status")
            self._plain_header = True
        self.console.print(
            f"  {escape(row.name):<{width}}  {records_text(row):>10}  {status_text(row.status)}"
        )

    def finalize(self) -> None:
        self._refresh()
        if self._live is not None:
            self._live.stop()
            self._live = None

    def rows(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name in self.matrix.order:
            row = self.matrix.rows[name]
            out.append(
                {
                    "collector": name,
                    "status": row.status,
                    "records": row.records,
                    "detail": row.detail,
                }
            )
        return out
