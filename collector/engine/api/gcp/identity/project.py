"""GCP project / organization context collector."""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import matches_any, param_raw, param_strings
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled


class ProjectCollector(Collector):
    name = "project"
    priority = 1
    description = "GCP project, organization, and operator context."
    required_actions = ("resourcemanager.projects.get",)

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        identity = cf.caller_identity()
        projects = self.ctx.project_ids
        allowed = param_strings(params, "project_ids")
        if allowed:
            projects = [p for p in projects if matches_any(p, allowed)]

        org_override = param_raw(params, "organization_id")
        snapshot: dict[str, Any] = {
            "organization_id": str(org_override).strip() if org_override else identity.organization_id,
            "operator_principal": identity.principal,
            "default_project": identity.project_id,
            "projects_in_scope": projects,
            "artifact_parameters": params,
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
                "organization_id": snapshot["organization_id"],
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes="Project + organization context.",
        )
