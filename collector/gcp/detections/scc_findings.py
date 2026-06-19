"""Security Command Center findings."""

from __future__ import annotations

from typing import Any

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import GcpAccessDenied, GcpServiceNotEnabled

MAX_RECORDS = 200_000


class SccFindingsCollector(Collector):
    name = "scc_findings"
    priority = 1
    description = "Security Command Center findings and threat detections."
    required_actions = ("securitycenter.findings.list",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        identity = cf.caller_identity()
        org_id = identity.organization_id

        if not org_id:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        "scc_findings",
                        GapReason.NOT_PRESENT,
                        "No organization id resolved — SCC requires org-level access.",
                    )
                ],
                notes="Organization context required for Security Command Center.",
            )

        findings: list[dict[str, Any]] = []
        try:
            for finding in cf.scc_findings(organization_id=org_id, max_records=MAX_RECORDS):
                finding["_ventra_organization_id"] = org_id
                findings.append(finding)
        except GcpAccessDenied as exc:
            gaps.append(("scc_findings", GapReason.ACCESS_DENIED, exc.message))
        except GcpServiceNotEnabled as exc:
            gaps.append(("scc_findings", GapReason.SERVICE_NOT_ENABLED, exc.message))

        files = [self.write_json({"organization_id": org_id}, "config.json")]
        if findings:
            files.append(self.write_jsonl(findings, "events.jsonl.gz"))

        self.write_meta({"source": self.name, "findings": len(findings), "organization_id": org_id})

        if findings:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
            notes = f"{len(findings)} SCC finding(s) for organization {org_id}."
        else:
            status = SourceStatus.EMPTY
            notes = "No SCC findings in scope."
            if not gaps:
                gaps.append(("scc_findings", GapReason.NOT_PRESENT, "No active SCC findings."))

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(findings),
            gaps=gaps,
            notes=notes,
        )
