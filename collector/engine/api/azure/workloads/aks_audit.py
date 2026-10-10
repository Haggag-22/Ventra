"""AKS Kubernetes audit log collector (cloud-side only).

Discovers AKS managed clusters via ARM, checks whether kube-audit logging is enabled and
routed to a Storage account via diagnostic settings, pulls matching JSON blobs, and records
clusters without audit logging as Log-Coverage gaps. Does not run in-cluster.
"""

from __future__ import annotations

import json
from typing import Any

from collector.clouds.azure.client_factory import AzureAccessDenied, AzureServiceNotEnabled
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import param_strings, scoped_window
from collector.lib.scoping import matches_any

from ..common.diagnostics import _container_for
from ..common.storage_logs import read_log_records, resource_id_prefixes

_AUDIT_CATEGORIES = {"kube-audit", "kube-audit-admin"}


def _as_audit_event(rec: dict[str, Any]) -> dict[str, Any]:
    """Return the kube-audit event inside a diagnostic envelope, or ``rec`` itself.

    Storage diagnostic blobs wrap each audit line as ``properties.log``, a JSON string
    of the Kubernetes audit object the normalizer expects.
    """
    props = rec.get("properties")
    if not isinstance(props, dict):
        return rec
    log = props.get("log")
    if not isinstance(log, str):
        return rec
    try:
        inner = json.loads(log)
    except json.JSONDecodeError:
        return rec
    if not isinstance(inner, dict):
        return rec
    out = dict(inner)
    for key in ("_ventra_cluster", "_ventra_resource_id"):
        if rec.get(key) and key not in out:
            out[key] = rec[key]
    return out


def _audit_routed(settings: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Return [(storage_account_id, category), …] for enabled kube-audit categories."""
    out: list[tuple[str, str]] = []
    for setting in settings:
        storage_id = setting.get("storage_account_id") or ""
        if not storage_id:
            continue
        enabled = [cat for cat in (setting.get("categories") or []) if cat.lower() in _AUDIT_CATEGORIES]
        groups = {str(group).lower() for group in (setting.get("category_groups") or [])}
        if "alllogs" in groups:
            seen = {cat.lower() for cat in enabled}
            enabled.extend(cat for cat in _AUDIT_CATEGORIES if cat not in seen)
        for cat in enabled:
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
        artifact_params = self.artifact_params()
        start, end = scoped_window(self.ctx, self.name, default_days=7)
        cluster_names = param_strings(artifact_params, "cluster_names")
        cluster_ids = param_strings(artifact_params, "cluster_ids")
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
                if cluster_names and not matches_any(name, cluster_names):
                    continue
                if cluster_ids and not matches_any(rid, cluster_ids):
                    continue
                entry = {
                    "name": name,
                    "id": rid,
                    "subscription_id": sub,
                    "location": cluster.get("location", ""),
                    "kubernetes_version": (cluster.get("properties") or {}).get("kubernetesVersion", ""),
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
                        for rec in read_log_records(
                            cc, prefixes=resource_id_prefixes(rid), start=start, end=end
                        ):
                            rec["_ventra_cluster"] = name
                            rec["_ventra_resource_id"] = rid
                            records.append(_as_audit_event(rec))
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
            "window": (
                {"since": start.isoformat(), "until": end.isoformat()}
                if start and end
                else self.ctx.time_window.to_manifest()
            ),
            "artifact_parameters": artifact_params,
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
