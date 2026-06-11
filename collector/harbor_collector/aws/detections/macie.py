"""Amazon Macie findings collector (Tier 2).

Macie publishes sensitive-data and policy findings per region. Security Hub can aggregate
these, but collecting Macie directly preserves full finding detail when Macie runs
standalone or findings are not forwarded to Security Hub.
"""

from __future__ import annotations

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class MacieCollector(Collector):
    name = "macie"
    tier = 2
    description = "Macie sensitive-data and policy findings."
    required_actions = (
        "macie2:GetMacieSession",
        "macie2:ListFindings",
        "macie2:GetFindings",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        findings: list[dict] = []
        sessions: list[dict] = []
        enabled_anywhere = False

        for region in self.ctx.regions:
            try:
                session = cf.call("macie2", region, "get_macie_session")
            except AccessDenied as exc:
                gaps.append(("macie", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue

            if session.get("status") != "ENABLED":
                continue

            enabled_anywhere = True
            sessions.append({"region": region, "session": session})
            findings.extend(self._findings(cf, region, gaps))

        if not enabled_anywhere:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("macie", GapReason.SERVICE_NOT_ENABLED, "Macie not enabled in scope.")],
                notes="Macie not enabled — recorded as a gap.",
            )

        files = [self.write_json({"sessions": sessions}, "config.json")]
        if findings:
            files.append(self.write_jsonl(findings, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "findings": len(findings), "regions": len(sessions)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(findings),
            gaps=gaps,
            notes=f"{len(findings)} Macie finding(s) across {len(sessions)} region(s).",
        )

    def _findings(self, cf, region: str, gaps: list) -> list[dict]:
        out: list[dict] = []
        try:
            ids = list(cf.paginate("macie2", region, "list_findings", "findingIds"))
        except AccessDenied as exc:
            gaps.append(("macie", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            return out
        except ServiceNotEnabled:
            return out

        for i in range(0, len(ids), 50):
            chunk = ids[i : i + 50]
            try:
                got = cf.call("macie2", region, "get_findings", findingIds=chunk).get("findings", [])
                for f in got:
                    f["_harbor_region"] = region
                out.extend(got)
            except (AccessDenied, ServiceNotEnabled):
                continue
        return out
