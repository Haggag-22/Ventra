"""EC2 inventory + EBS evidence-trail collector (Tier 2).

Inventory of instances, volumes, ENIs, security groups, AMIs and launch templates — plus the
EBS snapshot trail (creation, cross-account sharing, cross-region copy), a classic
exfiltration pattern the console's Resources panel highlights. Instance user-data is captured
where readable since it frequently carries bootstrap secrets and attacker persistence.

Note: this is metadata only. Disk *images* and OS internals are out of scope (Velociraptor).
"""

from __future__ import annotations

from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled

# Per-resource attribute lookups are one API call each; bound them so accounts with
# thousands of snapshots/instances stay collectable from a CloudShell.
MAX_SNAPSHOT_ATTR_LOOKUPS = 500
MAX_USER_DATA_LOOKUPS = 500


class Ec2Collector(Collector):
    name = "ec2"
    tier = 2
    description = "EC2/EBS inventory and snapshot share/copy evidence trail (metadata only)."
    required_actions = (
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute",
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
            "images": [],
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
                # Owners=self is load-bearing: without it this returns every public AMI.
                inventory["images"].extend(self._tag_region(
                    cf.paginate("ec2", region, "describe_images", "Images",
                                Owners=["self"]), region))
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

        share_stats = self._enrich_snapshot_permissions(cf, inventory["snapshots"], gaps)
        userdata_count = self._enrich_user_data(cf, inventory["instances"], gaps)

        shared = [s for s in inventory["snapshots"] if s.get("_harbor_shared")]
        public = [s for s in inventory["snapshots"] if s.get("_harbor_public")]
        wf = self.write_json(inventory, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "instances": len(inventory["instances"]),
                "volumes": len(inventory["volumes"]),
                "snapshots": len(inventory["snapshots"]),
                "images": len(inventory["images"]),
                "shared_snapshots": len(shared),
                "public_snapshots": len(public),
                "snapshot_permission_lookups": share_stats,
                "user_data_captured": userdata_count,
            }
        )
        notes = f"{len(inventory['instances'])} instances, {len(inventory['snapshots'])} snapshots"
        if shared or public:
            notes += (
                f"; {len(shared)} snapshot(s) shared cross-account, "
                f"{len(public)} public — review for exfil"
            )
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

    def _enrich_snapshot_permissions(
        self, cf, snapshots: list[dict], gaps: list[tuple[str, GapReason, str]]
    ) -> dict:
        """Resolve createVolumePermission per snapshot — the authoritative sharing record.

        DescribeSnapshots does not say who a snapshot is shared with; only
        DescribeSnapshotAttribute does. A permission of Group=all means public.
        """
        stats = {"looked_up": 0, "truncated": False}
        denied_once = False
        for snap in snapshots:
            if stats["looked_up"] >= MAX_SNAPSHOT_ATTR_LOOKUPS:
                stats["truncated"] = True
                gaps.append(
                    (
                        "ec2_snapshots",
                        GapReason.COLLECTOR_ERROR,
                        f"Snapshot share-permission lookups capped at "
                        f"{MAX_SNAPSHOT_ATTR_LOOKUPS} of {len(snapshots)} snapshots.",
                    )
                )
                break
            sid = snap.get("SnapshotId")
            region = snap.get("_harbor_region")
            if not sid:
                continue
            try:
                stats["looked_up"] += 1
                perms = cf.call(
                    "ec2", region, "describe_snapshot_attribute",
                    SnapshotId=sid, Attribute="createVolumePermission",
                ).get("CreateVolumePermissions", [])
            except AccessDenied as exc:
                if not denied_once:
                    denied_once = True
                    gaps.append(("ec2_snapshots", GapReason.ACCESS_DENIED, exc.message))
                break
            except ServiceNotEnabled:
                continue
            snap["CreateVolumePermissions"] = perms
            if perms:
                snap["_harbor_shared"] = True
            if any(p.get("Group") == "all" for p in perms):
                snap["_harbor_public"] = True
        return stats

    def _enrich_user_data(
        self, cf, instances: list[dict], gaps: list[tuple[str, GapReason, str]]
    ) -> int:
        """Attach base64 user-data to each instance where readable."""
        captured = 0
        looked_up = 0
        denied_once = False
        for inst in instances:
            if looked_up >= MAX_USER_DATA_LOOKUPS:
                gaps.append(
                    (
                        "ec2_user_data",
                        GapReason.COLLECTOR_ERROR,
                        f"User-data lookups capped at {MAX_USER_DATA_LOOKUPS} "
                        f"of {len(instances)} instances.",
                    )
                )
                break
            iid = inst.get("InstanceId")
            region = inst.get("_harbor_region")
            if not iid:
                continue
            try:
                looked_up += 1
                value = cf.call(
                    "ec2", region, "describe_instance_attribute",
                    InstanceId=iid, Attribute="userData",
                ).get("UserData", {}).get("Value")
            except AccessDenied as exc:
                if not denied_once:
                    denied_once = True
                    gaps.append(("ec2_user_data", GapReason.ACCESS_DENIED, exc.message))
                break
            except ServiceNotEnabled:
                continue
            if value:
                inst["_harbor_user_data_b64"] = value
                captured += 1
        return captured
