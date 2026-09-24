"""GCP IAM snapshot collector.

Point-in-time IAM posture per in-scope project: project bindings, service accounts,
user-managed key metadata (no private key material), project custom roles, and
per-service-account IAM policies where accessible.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.scoping import filter_iam_bindings
from collector.clouds.gcp.client_factory import GcpAccessDenied


class IamPolicyCollector(Collector):
    name = "iam_policy"
    priority = 1
    description = (
        "IAM snapshot: project bindings, service accounts, key metadata, custom roles."
    )
    required_actions = (
        "resourcemanager.projects.getIamPolicy",
        "iam.serviceAccounts.list",
        "iam.serviceAccounts.getIamPolicy",
        "iam.serviceAccountKeys.list",
        "iam.roles.list",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        projects = self.ctx.project_ids
        if not projects:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[("iam_policy", GapReason.NOT_PRESENT, "No projects in scope.")],
            )

        snapshots: list[dict[str, Any]] = []
        total_bindings = 0
        total_service_accounts = 0
        total_keys = 0
        total_custom_roles = 0

        for project_id in projects:
            entry = self._collect_project(project_id, cf, params, gaps)
            snapshots.append(entry)
            total_bindings += len(entry.get("bindings") or [])
            total_service_accounts += len(entry.get("service_accounts") or [])
            total_keys += sum(len(sa.get("keys") or []) for sa in entry.get("service_accounts") or [])
            total_custom_roles += len(entry.get("custom_roles") or [])

        wf = self.write_json(
            {"projects": snapshots, "artifact_parameters": params},
            "snapshot.json",
        )
        self.write_meta(
            {
                "source": self.name,
                "projects": len(snapshots),
                "bindings": total_bindings,
                "service_accounts": total_service_accounts,
                "service_account_keys": total_keys,
                "custom_roles": total_custom_roles,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            record_count=total_service_accounts + total_bindings,
            gaps=gaps,
            notes=(
                f"IAM snapshot for {len(snapshots)} project(s): "
                f"{total_service_accounts} service account(s), "
                f"{total_bindings} project binding(s), "
                f"{total_custom_roles} custom role(s)."
            ),
        )

    def _collect_project(
        self,
        project_id: str,
        cf,
        params: dict[str, Any],
        gaps: list[tuple[str, GapReason, str]],
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {"project_id": project_id}

        try:
            project_iam = cf.iam_policy_snapshot(project_id)
            project_iam["bindings"] = filter_iam_bindings(
                project_iam.get("bindings") or [], params
            )
            entry["project_iam"] = {
                "bindings": project_iam["bindings"],
                "etag": project_iam.get("etag"),
            }
            entry["bindings"] = project_iam["bindings"]
            entry["etag"] = project_iam.get("etag")
        except GcpAccessDenied as exc:
            gaps.append(("iam_policy", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))
            entry["project_iam"] = {"bindings": [], "etag": ""}
            entry["bindings"] = []
            entry["etag"] = ""

        service_accounts: list[dict[str, Any]] = []
        try:
            for sa in cf.list_service_accounts(project_id):
                sa_name = str(sa.get("name") or "")
                detail = dict(sa)
                if sa_name:
                    try:
                        detail["keys"] = cf.list_service_account_keys(sa_name)
                    except GcpAccessDenied as exc:
                        gaps.append(
                            (
                                "iam_policy_keys",
                                GapReason.ACCESS_DENIED,
                                f"{sa_name}: {exc.message}",
                            )
                        )
                        detail["keys"] = []
                    try:
                        sa_policy = cf.service_account_iam_policy(sa_name)
                        sa_policy["bindings"] = filter_iam_bindings(
                            sa_policy.get("bindings") or [], params
                        )
                        detail["iam_policy"] = sa_policy
                    except GcpAccessDenied as exc:
                        gaps.append(
                            (
                                "iam_policy_sa",
                                GapReason.ACCESS_DENIED,
                                f"{sa_name}: {exc.message}",
                            )
                        )
                service_accounts.append(detail)
        except GcpAccessDenied as exc:
            gaps.append(
                ("iam_policy_service_accounts", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}")
            )
        entry["service_accounts"] = service_accounts

        try:
            entry["custom_roles"] = cf.list_project_custom_roles(project_id)
        except GcpAccessDenied as exc:
            gaps.append(
                ("iam_policy_roles", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}")
            )
            entry["custom_roles"] = []

        return entry
