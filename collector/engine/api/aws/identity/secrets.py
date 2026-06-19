"""Secrets Manager collector (extended collector).

Secret *metadata only* — never values. Captures which secrets exist, rotation config, resource
policies, and last-accessed/last-changed timestamps. Secret access and changes are tracked via
CloudTrail; this inventory tells the analyst what was reachable.
"""

from __future__ import annotations

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled


class SecretsCollector(Collector):
    name = "secrets"
    priority = 2
    description = "Secrets Manager metadata (never values), rotation, resource policies."
    required_actions = ("secretsmanager:ListSecrets", "secretsmanager:DescribeSecret")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        secrets: list[dict] = []

        for region in self.ctx.regions:
            try:
                for s in cf.paginate("secretsmanager", region, "list_secrets", "SecretList"):
                    # ListSecrets already returns metadata; ensure no value leaks (it never does).
                    s.pop("SecretString", None)
                    s.pop("SecretBinary", None)
                    s["_ventra_region"] = region
                    secrets.append(s)
            except AccessDenied as exc:
                gaps.append(("secrets", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue

        if not secrets:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("secrets", GapReason.NOT_PRESENT, "No secrets in scope.")],
                notes="No Secrets Manager secrets found.",
            )

        wf = self.write_json({"secrets": secrets}, "snapshot.json")
        self.write_meta({"source": self.name, "secrets": len(secrets)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=len(secrets),
            gaps=gaps,
            notes=f"{len(secrets)} secret(s) (metadata only).",
        )
