"""Azure RBAC snapshot — role definitions and assignments."""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, AzureClientFactory
from ..common.serialize import to_dict


class RbacCollector(Collector):
    name = "rbac"
    priority = 1
    description = "Azure RBAC role definitions and assignments at subscription scope."
    required_actions = (
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
    )

    def collect(self) -> SourceResult:
        cf: AzureClientFactory = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        sub = cf.subscription_id
        scope = f"/subscriptions/{sub}"

        role_defs: list[dict] = []
        assignments: list[dict] = []
        try:
            auth = cf.authorization()
            for rd in auth.role_definitions.list(scope=scope):
                role_defs.append(to_dict(rd))
            for ra in auth.role_assignments.list(filter=f"atScope()"):
                item = to_dict(ra)
                if str(item.get("scope", "")).startswith(scope):
                    assignments.append(item)
        except AccessDenied as exc:
            gaps.append(("rbac", GapReason.ACCESS_DENIED, exc.message))
        except Exception as exc:
            msg = str(exc)
            if "AuthorizationFailed" in msg or "403" in msg:
                gaps.append(("rbac", GapReason.ACCESS_DENIED, msg))
            else:
                gaps.append(("rbac", GapReason.COLLECTOR_ERROR, msg))

        # Shape compatible with Identity panel tables (roles list).
        roles = []
        for rd in role_defs:
            props = rd.get("properties") or {}
            roles.append(
                {
                    "RoleName": props.get("roleName") or rd.get("name", ""),
                    "Arn": rd.get("id", ""),
                    "Description": props.get("description", ""),
                    "RoleType": props.get("type", ""),
                }
            )

        snapshot = {
            "subscription_id": sub,
            "role_definitions": role_defs,
            "role_assignments": assignments,
            "roles": roles,
            "users": [],
            "groups": [],
            "policies": [],
        }

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "role_definitions": len(role_defs),
                "role_assignments": len(assignments),
                "sha256": wf.sha256,
            }
        )
        status = SourceStatus.COLLECTED if role_defs or assignments else SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=[wf],
            gaps=gaps,
            notes=f"{len(role_defs)} role definition(s), {len(assignments)} assignment(s).",
        )
