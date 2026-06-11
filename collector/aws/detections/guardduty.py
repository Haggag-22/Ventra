"""GuardDuty collector.

Pulls every detector's findings across regions, plus the detector configuration and any
suppression filters (suppressed findings can hide attacker activity, so we record the filters
themselves). Whether GuardDuty is even enabled is recorded as a gap when absent.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class GuardDutyCollector(Collector):
    name = "guardduty"
    tier = 1
    description = "GuardDuty findings, detector config, suppression filters."
    required_actions = (
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "guardduty:ListFilters",
        "guardduty:GetFilter",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        findings: list[dict] = []
        detectors_meta: list[dict] = []
        enabled_anywhere = False

        for region in self.ctx.regions:
            try:
                detector_ids = list(
                    cf.paginate("guardduty", region, "list_detectors", "DetectorIds")
                )
            except AccessDenied as exc:
                gaps.append(("guardduty", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            except ClientError as exc:
                gaps.append(("guardduty", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
                continue
            for did in detector_ids:
                enabled_anywhere = True
                try:
                    detector = cf.call("guardduty", region, "get_detector", DetectorId=did)
                except (AccessDenied, ServiceNotEnabled, ClientError) as exc:
                    gaps.append(("guardduty", GapReason.COLLECTOR_ERROR, f"{did}: {exc}"))
                    detector = {}
                filters = self._filters(cf, region, did)
                detectors_meta.append(
                    {"region": region, "detector_id": did, "detector": detector, "filters": filters}
                )
                findings.extend(self._findings(cf, region, did))

        if not enabled_anywhere:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("guardduty", GapReason.SERVICE_NOT_ENABLED, "GuardDuty not enabled in scope.")],
                notes="GuardDuty not enabled — recorded as a gap.",
            )

        files = [self.write_json({"detectors": detectors_meta}, "config.json")]
        if findings:
            files.append(self.write_jsonl(findings, "events.jsonl.gz"))
        self.write_meta(
            {"source": self.name, "detectors": len(detectors_meta), "findings": len(findings)}
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(findings),
            gaps=gaps,
            notes=f"{len(findings)} findings across {len(detectors_meta)} detector(s).",
        )

    def _filters(self, cf, region, did) -> list[dict]:
        out = []
        try:
            for fname in cf.paginate("guardduty", region, "list_filters", "FilterNames",
                                     DetectorId=did):
                out.append(cf.call("guardduty", region, "get_filter",
                                   DetectorId=did, FilterName=fname))
        except (AccessDenied, ServiceNotEnabled, ClientError):
            pass
        return out

    def _findings(self, cf, region, did) -> list[dict]:
        out: list[dict] = []
        try:
            ids = list(cf.paginate("guardduty", region, "list_findings", "FindingIds",
                                   DetectorId=did))
        except (AccessDenied, ServiceNotEnabled, ClientError):
            return out
        # GetFindings accepts up to 50 ids per call.
        for i in range(0, len(ids), 50):
            chunk = ids[i : i + 50]
            try:
                got = cf.call("guardduty", region, "get_findings",
                              DetectorId=did, FindingIds=chunk).get("Findings", [])
                for f in got:
                    f["_harbor_region"] = region
                out.extend(got)
            except (AccessDenied, ServiceNotEnabled, ClientError):
                continue
        return out
