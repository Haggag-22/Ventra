"""AKS Kubernetes audit log collector (cloud-side only).

Discovers AKS managed clusters via ARM, checks whether kube-audit logging is enabled and
routed to a Storage account via diagnostic settings, pulls matching JSON blobs, and records
clusters without audit logging as Log-Coverage gaps. Does not run in-cluster.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from ..common.diagnostics import _container_for
from ..common.storage_logs import read_log_records

_AUDIT_CATEGORIES = {"kube-audit", "kube-audit-admin"}


def _audit_routed(settings: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Return [(storage_account_id, category), …] for enabled kube-audit categories."""
    out: list[tuple[str, str]] = []
    for setting in settings:
        storage_id = setting.get("storage_account_id") or ""
        if not storage_id:
            continue
        for cat in setting.get("categories") or []:
            if cat.lower() in _AUDIT_CATEGORIES:
                out.append((storage_id, cat))
    return out


class AksAuditCollector(Collector):
    name = "aks_audit"
    priority = 2
    description = "AKS kube-audit logs from Storage diagnostics + cluster audit posture."
    required_actions = (
        "Microsoft.ContainerService/managedClusters/read",
        "Microsoft.Insights/DiagnosticSettings/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        clusters: list[dict[str, Any]] = []
        records: list[dict] = []
        per_cluster: list[dict[str, Any]] = []

        for sub in self.ctx.subscription_ids:
            try:
                found = cf.managed_clusters(sub)
            except AzureAccessDenied as exc:
                gaps.append(("aks_audit", GapReason.ACCESS_DENIED, f"{sub}: {exc.message}"))
                continue
            except AzureServiceNotEnabled:
                continue
            for cluster in found:
                rid = cluster.get("id") or ""
                name = cluster.get("name") or rid.rsplit("/", 1)[-1]
                entry = {
                    "name": name,
                    "id": rid,
                    "subscription_id": sub,
                    "location": cluster.get("location", ""),
                    "kubernetes_version": (cluster.get("properties") or {}).get(
                        "kubernetesVersion", ""
                    ),
                }
                try:
                    settings = cf.diagnostic_settings(rid)
                except AzureAccessDenied as exc:
                    gaps.append(("aks_audit", GapReason.ACCESS_DENIED, f"{name}: {exc.message}"))
                    settings = []
                except AzureServiceNotEnabled:
                    settings = []

                routes = _audit_routed(settings)
                entry["audit_routed"] = bool(routes)
                clusters.append(entry)

                if not routes:
                    gaps.append(
                        (
                            "aks_audit",
                            GapReason.LOGGING_NOT_CONFIGURED,
                            f"{name}: kube-audit not routed to Storage — in-cluster activity blind spot.",
                        )
                    )
                    continue

                before = len(records)
                for storage_id, category in routes:
                    try:
                        cc = cf.container_client(storage_id, _container_for(category))
                        for rec in read_log_records(cc, prefix=f"resourceId={rid.upper()}"):
                            rec["_ventra_cluster"] = name
                            rec["_ventra_resource_id"] = rid
                            records.append(rec)
                    except AzureAccessDenied as exc:
                        gaps.append(("aks_audit", GapReason.ACCESS_DENIED, f"{name}: {exc.message}"))
                    except AzureServiceNotEnabled:
                        pass
                per_cluster.append({**entry, "records": len(records) - before})

        if not clusters and not any(g[1] == GapReason.ACCESS_DENIED for g in gaps):
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps or [("aks_audit", GapReason.NOT_PRESENT, "No AKS clusters in scope.")],
                notes="No AKS clusters found.",
            )

        config = {
            "clusters": clusters,
            "audit_enabled_count": sum(1 for c in clusters if c.get("audit_routed")),
            "audit_disabled_count": sum(1 for c in clusters if not c.get("audit_routed")),
            "collection": per_cluster,
            "window": self.ctx.time_window.to_manifest(),
        }
        files = [self.write_json(config, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "clusters": len(clusters),
                "window": self.ctx.time_window.to_manifest(),
            }
        )

        audited = [c for c in clusters if c.get("audit_routed")]
        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif audited:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(("aks_audit", GapReason.NOT_PRESENT, "No kube-audit events in window."))
        else:
            status = SourceStatus.EMPTY

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} kube-audit event(s) from "
            f"{len(audited)}/{len(clusters)} cluster(s) with audit logging.",
        )
