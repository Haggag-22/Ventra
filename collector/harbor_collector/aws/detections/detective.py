"""Amazon Detective investigations collector (Tier 2).

Detective does not expose GuardDuty-style findings; open investigations are the closest
IR-ready signal. This collector lists graph membership and active investigations per region.
"""

from __future__ import annotations

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class DetectiveCollector(Collector):
    name = "detective"
    tier = 2
    description = "Detective graph config and open investigations."
    required_actions = (
        "detective:ListGraphs",
        "detective:ListInvestigations",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        investigations: list[dict] = []
        graphs: list[dict] = []
        enabled_anywhere = False

        for region in self.ctx.regions:
            try:
                graph_list = cf.call("detective", region, "list_graphs").get("GraphList", [])
            except AccessDenied as exc:
                gaps.append(("detective", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue

            if not graph_list:
                continue

            enabled_anywhere = True
            for graph in graph_list:
                graph_arn = graph.get("Arn", "")
                graphs.append({"region": region, **graph})
                for inv in cf.paginate(
                    "detective",
                    region,
                    "list_investigations",
                    "InvestigationDetails",
                    GraphArn=graph_arn,
                ):
                    inv["_harbor_region"] = region
                    inv["_harbor_graph_arn"] = graph_arn
                    investigations.append(inv)

        if not enabled_anywhere:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("detective", GapReason.SERVICE_NOT_ENABLED, "Detective not enabled in scope.")],
                notes="Detective not enabled — recorded as a gap.",
            )

        files = [self.write_json({"graphs": graphs}, "config.json")]
        if investigations:
            files.append(self.write_jsonl(investigations, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "graphs": len(graphs),
                "investigations": len(investigations),
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(investigations),
            gaps=gaps,
            notes=f"{len(investigations)} investigation(s) across {len(graphs)} graph(s).",
        )
