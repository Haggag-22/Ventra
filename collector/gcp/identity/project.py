"""GCP project / organization context collector."""

from __future__ import annotations

from typing import Any

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import GcpAccessDenied, GcpServiceNotEnabled


class ProjectCollector(Collector):
    name = "project"
    priority = 1
    description = "GCP project, organization, and operator context."
    required_actions = ("resourcemanager.projects.get",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        identity = cf.caller_identity()
        projects = self.ctx.project_ids

        snapshot: dict[str, Any] = {
            "organization_id": identity.organization_id,
            "operator_principal": identity.principal,
            "default_project": identity.project_id,
            "projects_in_scope": projects,
        }

        try:
            snapshot["projects"] = cf.project_details(projects)
        except GcpAccessDenied as exc:
            gaps.append(("project", GapReason.ACCESS_DENIED, exc.message))
            snapshot["projects"] = []
        except GcpServiceNotEnabled as exc:
            gaps.append(("project", GapReason.SERVICE_NOT_ENABLED, exc.message))
            snapshot["projects"] = []

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "projects": len(snapshot.get("projects") or []),
                "organization_id": identity.organization_id,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes="Project + organization context.",
        )
