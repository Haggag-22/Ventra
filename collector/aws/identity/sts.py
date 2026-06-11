"""STS activity collector.

STS has no "list assume-role events" API — the authoritative record lives in CloudTrail. This
collector pulls AssumeRole / AssumeRoleWithSAML / AssumeRoleWithWebIdentity events via
CloudTrail LookupEvents so the console's role-assumption graph can be built even when only
this focused slice is collected.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled

ASSUME_EVENTS = ("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity")


class StsCollector(Collector):
    name = "sts"
    tier = 1
    description = "AssumeRole activity (sourced from CloudTrail LookupEvents)."
    required_actions = ("cloudtrail:LookupEvents",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        window = self.ctx.time_window
        start = window.since or datetime(2000, 1, 1, tzinfo=UTC)
        end = window.until or datetime.now(UTC)

        records = []
        gaps: list[tuple[str, GapReason, str]] = []
        for region in self.ctx.regions:
            for event_name in ASSUME_EVENTS:
                try:
                    for ev in cf.paginate(
                        "cloudtrail",
                        region,
                        "lookup_events",
                        "Events",
                        LookupAttributes=[
                            {"AttributeKey": "EventName", "AttributeValue": event_name}
                        ],
                        StartTime=start,
                        EndTime=end,
                    ):
                        ev["_harbor_region"] = region
                        records.append(ev)
                except AccessDenied as exc:
                    gaps.append(("sts", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                except ServiceNotEnabled:
                    continue

        if not records:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("sts", GapReason.NOT_PRESENT, "No AssumeRole events in window.")],
                notes="No AssumeRole activity found in the time window.",
            )

        wf = self.write_jsonl(records, "events.jsonl.gz")
        self.write_meta(
            {"source": self.name, "records": len(records), "regions": self.ctx.regions}
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} AssumeRole events.",
        )
