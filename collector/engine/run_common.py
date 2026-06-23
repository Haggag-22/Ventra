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
        *,
        plan_label: str = "",
        artifact_labels: dict[str, str] | None = None,
        artifact_severities: dict[str, str] | None = None,
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
    def _p(val: str | None, *, end_of_day: bool = False) -> datetime | None:
        if not val:
            return None
        val = val.strip()
        try:
            dt = datetime.strptime(val, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            try:
                dt = datetime.strptime(val, "%Y-%m-%d").replace(tzinfo=UTC)
                if end_of_day:
                    dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            except ValueError:
                raise ValueError(f"Unrecognized date: {val!r}. Use YYYY-MM-DD or RFC3339.") from None
        return dt

    return TimeWindow(since=_p(since), until=_p(until, end_of_day=True))
