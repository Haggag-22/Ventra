"""GCP IAM policy bindings snapshot."""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.gcp.client_factory import GcpAccessDenied


class IamPolicyCollector(Collector):
    name = "iam_policy"
    priority = 1
    description = "IAM policy bindings and role assignments per in-scope project."
    required_actions = ("resourcemanager.projects.getIamPolicy",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        projects = self.ctx.project_ids
        if not projects:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("iam_policy", GapReason.NOT_PRESENT, "No projects in scope.")],
            )

        bindings: list[dict[str, Any]] = []
        for project_id in projects:
            try:
                policy = cf.iam_policy_snapshot(project_id)
                bindings.append(policy)
            except GcpAccessDenied as exc:
                gaps.append(("iam_policy", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))

        wf = self.write_json({"projects": bindings}, "snapshot.json")
        self.write_meta({"source": self.name, "projects": len(bindings)})
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes=f"IAM bindings for {len(bindings)} project(s).",
        )
