"""Entra directory snapshot collector.

Point-in-time inventory of users, groups, applications, and service principals via
Microsoft Graph pagination. Stored as ``snapshot.json`` for the console Identity / Resources
panels — answers "who and what exists in the tenant right now".
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled

MAX_RECORDS = 200_000


class EntraDirectoryCollector(Collector):
    name = "entra_directory"
    priority = 1
    description = "Entra ID users, groups, applications, and service principals snapshot."
    required_actions = (
        "User.Read.All",
        "Group.Read.All",
        "Application.Read.All",
        "Directory.Read.All",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        snapshot: dict[str, Any] = {
            "users": [],
            "groups": [],
            "applications": [],
            "service_principals": [],
        }

        endpoints = (
            ("users", "users"),
            ("groups", "groups"),
            ("applications", "applications"),
            ("service_principals", "servicePrincipals"),
        )
        for key, path in endpoints:
            try:
                snapshot[key] = list(
                    cf.graph_paginate(path, params={"$top": 999}, max_records=MAX_RECORDS)
                )
            except AzureAccessDenied as exc:
                gaps.append(("entra_directory", GapReason.ACCESS_DENIED, f"{path}: {exc.message}"))
            except AzureServiceNotEnabled as exc:
                gaps.append(
                    ("entra_directory", GapReason.SERVICE_NOT_ENABLED, f"{path}: {exc.message}")
                )

        total = sum(len(snapshot[k]) for k in snapshot)
        if total == 0 and gaps:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps,
                notes="Entra directory snapshot unavailable.",
            )

        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "users": len(snapshot["users"]),
                "groups": len(snapshot["groups"]),
                "applications": len(snapshot["applications"]),
                "service_principals": len(snapshot["service_principals"]),
                "sha256": wf.sha256,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            gaps=gaps,
            notes=(
                f"Entra snapshot: {len(snapshot['users'])} users, "
                f"{len(snapshot['groups'])} groups, "
                f"{len(snapshot['applications'])} apps, "
                f"{len(snapshot['service_principals'])} service principals."
            ),
        )
