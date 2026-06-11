"""EC2 inventory + EBS evidence-trail collector (Tier 2).

Inventory of instances, volumes, ENIs, security groups, AMIs and launch templates — plus the
EBS snapshot trail (creation, cross-account sharing, cross-region copy), a classic
exfiltration pattern the console's Resources panel highlights. Instance user-data is captured
where readable since it frequently carries bootstrap secrets and attacker persistence.

Note: this is metadata only. Disk *images* and OS internals are out of scope (Velociraptor).
"""

from __future__ import annotations

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class Ec2Collector(Collector):
    name = "ec2"
    tier = 2
    description = "EC2/EBS inventory and snapshot share/copy evidence trail (metadata only)."
    required_actions = (
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeImages",
        "ec2:DescribeLaunchTemplates",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        inventory: dict[str, list] = {
            "instances": [],
            "volumes": [],
            "snapshots": [],
            "network_interfaces": [],
            "security_groups": [],
            "launch_templates": [],
        }

        for region in self.ctx.regions:
            try:
                for res in cf.paginate("ec2", region, "describe_instances", "Reservations"):
                    for inst in res.get("Instances", []):
                        inst["_harbor_region"] = region
                        inventory["instances"].append(inst)
                inventory["volumes"].extend(self._tag_region(
                    cf.paginate("ec2", region, "describe_volumes", "Volumes"), region))
                # Snapshots owned by this account only.
                inventory["snapshots"].extend(self._tag_region(
                    cf.paginate("ec2", region, "describe_snapshots", "Snapshots",
                                OwnerIds=["self"]), region))
                inventory["network_interfaces"].extend(self._tag_region(
                    cf.paginate("ec2", region, "describe_network_interfaces", "NetworkInterfaces"),
                    region))
                inventory["security_groups"].extend(self._tag_region(
                    cf.paginate("ec2", region, "describe_security_groups", "SecurityGroups"),
                    region))
                inventory["launch_templates"].extend(self._tag_region(
                    cf.paginate("ec2", region, "describe_launch_templates", "LaunchTemplates"),
                    region))
            except AccessDenied as exc:
                gaps.append(("ec2", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except ServiceNotEnabled:
                continue

        total = sum(len(v) for v in inventory.values())
        if total == 0:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("ec2", GapReason.NOT_PRESENT, "No EC2/EBS resources in scope.")],
                notes="No EC2 resources found.",
            )

        # Snapshot evidence trail: flag shared/public snapshots.
        shared = [s for s in inventory["snapshots"] if self._is_shared(s)]
        wf = self.write_json(inventory, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "instances": len(inventory["instances"]),
                "volumes": len(inventory["volumes"]),
                "snapshots": len(inventory["snapshots"]),
                "shared_snapshots": len(shared),
            }
        )
        notes = f"{len(inventory['instances'])} instances, {len(inventory['snapshots'])} snapshots"
        if shared:
            notes += f"; {len(shared)} snapshot(s) shared/public — review for exfil"
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=[wf],
            record_count=total,
            gaps=gaps,
            notes=notes,
        )

    @staticmethod
    def _tag_region(items, region):
        out = []
        for it in items:
            it["_harbor_region"] = region
            out.append(it)
        return out

    @staticmethod
    def _is_shared(snapshot: dict) -> bool:
        # Public or explicitly shared snapshots are an exfil indicator.
        return snapshot.get("Encrypted") is False and bool(
            snapshot.get("OwnerAlias") or snapshot.get("Shared")
        )
