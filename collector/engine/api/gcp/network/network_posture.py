"""GCP network posture snapshot — firewall rules, topology, packet mirroring.

One combined collector for the Compute Network API inventory Google recommends during
live forensics: VPC firewall rules, network topology (VPCs, subnets with flow-log config,
routes, VPC peering), and packet mirroring policies. This is configuration metadata —
not flow or firewall *logs* (see vpc_flow / firewall_logs collectors).
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.scoping import filter_network_posture
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

MAX_FIREWALLS = 500
MAX_NETWORKS = 200
MAX_SUBNETS = 500
MAX_ROUTES = 500
MAX_PACKET_MIRRORINGS = 200


class NetworkPostureCollector(Collector):
    name = "network_posture"
    priority = 2
    description = (
        "VPC firewall rules, network topology (VPCs, subnets, routes, peering), "
        "and packet mirroring policies."
    )
    required_actions = (
        "compute.firewalls.list",
        "compute.networks.list",
        "compute.subnetworks.list",
        "compute.routes.list",
        "compute.packetMirrorings.list",
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
                gaps=[("network_posture", GapReason.NOT_PRESENT, "No projects in scope.")],
            )

        snapshot: dict[str, Any] = {
            "firewall_rules": [],
            "networks": [],
            "subnetworks": [],
            "routes": [],
            "packet_mirroring_policies": [],
        }

        for project_id in projects:
            sections = (
                ("firewall_rules", cf.compute_firewalls, MAX_FIREWALLS),
                ("networks", cf.compute_networks, MAX_NETWORKS),
                ("subnetworks", cf.compute_subnetworks, MAX_SUBNETS),
                ("routes", cf.compute_routes, MAX_ROUTES),
                ("packet_mirroring_policies", cf.compute_packet_mirrorings, MAX_PACKET_MIRRORINGS),
            )
            try:
                for key, fn, cap in sections:
                    rows = fn(project_id, max_items=cap)
                    for row in rows:
                        row["_ventra_project_id"] = project_id
                        snapshot[key].append(row)
                    if len(rows) >= cap:
                        gaps.append(
                            (
                                f"network_posture_{key}",
                                GapReason.COLLECTOR_ERROR,
                                f"{key} capped at {cap} for {project_id}.",
                            )
                        )
            except GcpAccessDenied as exc:
                gaps.append(
                    ("network_posture", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}")
                )
            except GcpServiceNotEnabled as exc:
                gaps.append(
                    ("network_posture", GapReason.SERVICE_NOT_ENABLED, f"{project_id}: {exc.message}")
                )

        snapshot = filter_network_posture(snapshot, params)
        total = sum(len(snapshot[k]) for k in snapshot if isinstance(snapshot[k], list))
        if total == 0:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [
                    ("network_posture", GapReason.NOT_PRESENT, "No network resources in scope.")
                ],
                notes="No network posture data found.",
            )

        snapshot["artifact_parameters"] = params
        wf = self.write_json(snapshot, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "firewall_rules": len(snapshot["firewall_rules"]),
                "networks": len(snapshot["networks"]),
                "subnetworks": len(snapshot["subnetworks"]),
                "routes": len(snapshot["routes"]),
                "packet_mirroring_policies": len(snapshot["packet_mirroring_policies"]),
            }
        )
        notes = (
            f"{len(snapshot['firewall_rules'])} firewall rule(s), "
            f"{len(snapshot['subnetworks'])} subnet(s), "
            f"{len(snapshot['packet_mirroring_policies'])} packet mirroring policy(ies)"
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            record_count=total,
            gaps=gaps,
            notes=notes,
        )
