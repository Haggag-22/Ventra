"""GCE inventory collector — Compute Engine metadata snapshot.

Mirrors the AWS EC2 collector: instances (network tags, service accounts, metadata keys,
zone), persistent disks, snapshots, and NICs. Disk *images* and OS internals are out of
scope — use Velociraptor or similar for disk acquisition.

During live forensics, this snapshot answers which VMs were running, which service
accounts they used, and whether metadata keys suggest startup-script persistence.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.scoping import filter_gce_inventory
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

MAX_INSTANCES = 500
MAX_DISKS = 500
MAX_SNAPSHOTS = 500


class GceCollector(Collector):
    name = "gce"
    priority = 2
    description = "GCE instance, disk, snapshot, and NIC inventory (metadata only)."
    required_actions = (
        "compute.instances.list",
        "compute.disks.list",
        "compute.snapshots.list",
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
                gaps=[("gce", GapReason.NOT_PRESENT, "No projects in scope.")],
            )

        inventory: dict[str, list] = {
            "instances": [],
            "disks": [],
            "snapshots": [],
            "network_interfaces": [],
        }

        for project_id in projects:
            try:
                instances = cf.compute_aggregated_instances(project_id, max_items=MAX_INSTANCES)
                for inst in instances:
                    inst["_ventra_project_id"] = project_id
                    self._redact_instance_metadata(inst)
                    inventory["instances"].append(inst)
                    inventory["network_interfaces"].extend(
                        self._extract_nics(inst, project_id)
                    )
                if len(instances) >= MAX_INSTANCES:
                    gaps.append(
                        (
                            "gce_instances",
                            GapReason.COLLECTOR_ERROR,
                            f"Instance inventory capped at {MAX_INSTANCES} for {project_id}.",
                        )
                    )

                disks = cf.compute_aggregated_disks(project_id, max_items=MAX_DISKS)
                for disk in disks:
                    disk["_ventra_project_id"] = project_id
                    inventory["disks"].append(disk)
                if len(disks) >= MAX_DISKS:
                    gaps.append(
                        (
                            "gce_disks",
                            GapReason.COLLECTOR_ERROR,
                            f"Disk inventory capped at {MAX_DISKS} for {project_id}.",
                        )
                    )

                snaps = cf.compute_snapshots(project_id, max_items=MAX_SNAPSHOTS)
                for snap in snaps:
                    snap["_ventra_project_id"] = project_id
                    inventory["snapshots"].append(snap)
                if len(snaps) >= MAX_SNAPSHOTS:
                    gaps.append(
                        (
                            "gce_snapshots",
                            GapReason.COLLECTOR_ERROR,
                            f"Snapshot inventory capped at {MAX_SNAPSHOTS} for {project_id}.",
                        )
                    )
            except GcpAccessDenied as exc:
                gaps.append(("gce", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))
            except GcpServiceNotEnabled as exc:
                gaps.append(("gce", GapReason.SERVICE_NOT_ENABLED, f"{project_id}: {exc.message}"))

        inventory = filter_gce_inventory(inventory, params)
        total = sum(len(v) for v in inventory.values())
        if total == 0:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("gce", GapReason.NOT_PRESENT, "No GCE resources in scope.")],
                notes="No GCE resources found.",
            )

        inventory["artifact_parameters"] = params
        wf = self.write_json(inventory, "snapshot.json")
        self.write_meta(
            {
                "source": self.name,
                "instances": len(inventory["instances"]),
                "disks": len(inventory["disks"]),
                "snapshots": len(inventory["snapshots"]),
                "network_interfaces": len(inventory["network_interfaces"]),
            }
        )
        notes = (
            f"{len(inventory['instances'])} instance(s), "
            f"{len(inventory['snapshots'])} snapshot(s), "
            f"{len(inventory['network_interfaces'])} NIC(s)"
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED,
            files=[wf],
            record_count=total,
            gaps=gaps,
            notes=notes,
        )

    @staticmethod
    def _redact_instance_metadata(inst: dict[str, Any]) -> None:
        """Keep metadata item keys only — values often hold secrets."""
        meta = inst.get("metadata") or {}
        items = meta.get("items") or []
        inst["_ventra_metadata_keys"] = [
            str(i.get("key")) for i in items if isinstance(i, dict) and i.get("key")
        ]
        if items:
            meta["items"] = [{"key": i.get("key")} for i in items if isinstance(i, dict)]

    @staticmethod
    def _extract_nics(inst: dict[str, Any], project_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        zone = inst.get("_ventra_zone") or ""
        inst_id = inst.get("id") or inst.get("name") or ""
        for nic in inst.get("networkInterfaces") or []:
            if not isinstance(nic, dict):
                continue
            row = dict(nic)
            row["_ventra_project_id"] = project_id
            row["_ventra_zone"] = zone
            row["_ventra_instance_id"] = inst_id
            out.append(row)
        return out
