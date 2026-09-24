"""Azure RBAC snapshot collector.

Captures role definitions and role assignments at subscription scope so the console can show
who holds which built-in/custom roles — the Azure equivalent of the AWS IAM snapshot lens.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import param_strings
from collector.lib.scoping import matches_any
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled


class RbacCollector(Collector):
    name = "rbac"
    priority = 1
    description = "Azure RBAC role definitions and assignments at subscription scope."
    required_actions = (
        "Microsoft.Authorization/roleDefinitions/read",
        "Microsoft.Authorization/roleAssignments/read",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        artifact_params = self.artifact_params()
        snapshot: dict[str, Any] = {
            "subscriptions": [],
            "role_definitions": [],
            "role_assignments": [],
        }

        subscriptions = self.ctx.subscription_ids
        if not subscriptions:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("rbac", GapReason.NOT_PRESENT, "No subscriptions in scope.")],
                notes="No subscriptions discovered or specified.",
            )

        for sub in subscriptions:
            try:
                data = cf.rbac_snapshot(sub)
            except AzureAccessDenied as exc:
                gaps.append(("rbac", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
                continue
            except AzureServiceNotEnabled as exc:
                gaps.append(("rbac", GapReason.NOT_PRESENT, f"{sub}: {exc.message}"))
                continue
            snapshot["subscriptions"].append(sub)
            for rd in data.get("role_definitions") or []:
                rd["_ventra_subscription_id"] = sub
                snapshot["role_definitions"].append(rd)
            for ra in data.get("role_assignments") or []:
                ra["_ventra_subscription_id"] = sub
                snapshot["role_assignments"].append(ra)

        principal_ids = param_strings(artifact_params, "principal_ids")
        role_names = param_strings(artifact_params, "role_names")
        if principal_ids:
            snapshot["role_assignments"] = [
                ra for ra in snapshot["role_assignments"]
                if matches_any(str((ra.get("properties") or ra).get("principalId") or ""), principal_ids)
            ]
        if role_names:
            rd_map = {str(rd.get("id") or ""): str(rd.get("properties", rd).get("roleName") or rd.get("roleName") or "")
                      for rd in snapshot["role_definitions"]}
            snapshot["role_assignments"] = [
                ra for ra in snapshot["role_assignments"]
                if matches_any(rd_map.get(str((ra.get("properties") or ra).get("roleDefinitionId") or ""), role_names)
                               or matches_any(str((ra.get("properties") or ra).get("roleDefinitionId") or ""), role_names))
            ]
        snapshot["artifact_parameters"] = artifact_params

        if not snapshot["role_definitions"] and not snapshot["role_assignments"] and gaps:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps,
                notes="RBAC snapshot unavailable.",
            )

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "role_definitions": len(snapshot["role_definitions"]),
                "role_assignments": len(snapshot["role_assignments"]),
                "subscriptions": len(snapshot["subscriptions"]),
                "sha256": wf.sha256,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes=(
                f"{len(snapshot['role_definitions'])} role definition(s), "
                f"{len(snapshot['role_assignments'])} assignment(s) "
                f"across {len(snapshot['subscriptions'])} subscription(s)."
            ),
        )
