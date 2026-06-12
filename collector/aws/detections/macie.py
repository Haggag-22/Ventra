"""Amazon Macie findings collector (extended collector).

Macie publishes sensitive-data and policy findings per region. Security Hub can aggregate
these, but collecting Macie directly preserves full finding detail when Macie runs
standalone or findings are not forwarded to Security Hub.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class MacieCollector(Collector):
    name = "macie"
    priority = 2
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
                # Macie reports a disabled session as AccessDeniedException with a
                # "Macie is not enabled" message — that is a coverage fact, not a
                # permissions problem, so don't mislabel it.
                if "not enabled" in exc.message.lower() or "disabled" in exc.message.lower():
                    continue
                gaps.append(("macie", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            except ClientError as exc:
                # An unexpected per-region error is a gap, not a reason to drop the
                # whole collector.
                gaps.append(("macie", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
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
        except ClientError as exc:
            gaps.append(("macie", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
            return out

        for i in range(0, len(ids), 50):
            chunk = ids[i : i + 50]
            try:
                got = cf.call("macie2", region, "get_findings", findingIds=chunk).get("findings", [])
                for f in got:
                    f["_ventra_region"] = region
                out.extend(got)
            except (AccessDenied, ServiceNotEnabled):
                continue
        return out
