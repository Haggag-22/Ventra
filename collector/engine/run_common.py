"""Shared orchestration helpers used by per-cloud runners."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..lib.models import SourceResult, TimeWindow


@dataclass
class RunReporter:
    """Pluggable progress sink. The CLI passes a rich-backed reporter; tests pass None."""

    events: list[tuple[str, str]] = field(default_factory=list)

    def begin_run(
        self,
        account_id: str,
        regions: list[str],
        case_id: str = "",
        collectors: list[str] | None = None,
    ) -> None:
        """Called once after identity/regions are resolved. No-op by default; the CLI's
        matrix reporter overrides it to print the run header and pre-populate the matrix
        with every planned collector."""

    def start(self, name: str) -> None:
        self._emit(name, "running")

    def finish(self, name: str, result: SourceResult) -> None:
        self._emit(name, result.status.value)

    def event(self, name: str, msg: str) -> None:
        self.events.append((name, msg))

    def _emit(self, name: str, status: str) -> None:  # overridden by CLI subclass
        self.events.append((name, status))


def parse_window(since: str | None, until: str | None) -> TimeWindow:
    def _p(val: str | None) -> datetime | None:
        if not val:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                return datetime.strptime(val, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        raise ValueError(f"Unrecognized date: {val!r}. Use YYYY-MM-DD or RFC3339.")

    return TimeWindow(since=_p(since), until=_p(until))
