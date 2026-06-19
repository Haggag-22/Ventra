"""Amazon Detective investigations collector (extended collector).

Detective does not expose GuardDuty-style findings; open investigations are the closest
IR-ready signal. This collector lists graph membership and active investigations per region.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled


class DetectiveCollector(Collector):
    name = "detective"
    priority = 2
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

        # Detective's List* operations have no botocore paginators — page manually.
        for region in self.ctx.regions:
            try:
                graph_list = list(
                    cf.paginate_manual("detective", region, "list_graphs", "GraphList")
                )
            except AccessDenied as exc:
                gaps.append(("detective", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except ServiceNotEnabled:
                continue
            except ClientError as exc:
                gaps.append(("detective", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))
                continue

            if not graph_list:
                continue

            enabled_anywhere = True
            for graph in graph_list:
                graph_arn = graph.get("Arn", "")
                graphs.append({"region": region, **graph})
                try:
                    for inv in cf.paginate_manual(
                        "detective",
                        region,
                        "list_investigations",
                        "InvestigationDetails",
                        GraphArn=graph_arn,
                    ):
                        inv["_ventra_region"] = region
                        inv["_ventra_graph_arn"] = graph_arn
                        investigations.append(inv)
                except AccessDenied as exc:
                    gaps.append(
                        ("detective", GapReason.ACCESS_DENIED, f"{graph_arn}: {exc.message}")
                    )
                except ServiceNotEnabled:
                    continue
                except ClientError as exc:
                    gaps.append(
                        ("detective", GapReason.COLLECTOR_ERROR, f"{graph_arn}: {exc}")
                    )

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
