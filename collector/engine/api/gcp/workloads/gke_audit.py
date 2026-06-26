"""GKE Kubernetes audit log collector.

Discovers GKE clusters, records which have API-server logging enabled (required for
``k8s_cluster`` audit events in Cloud Logging), pulls audit log entries for the case
window, and records clusters without logging as gaps.
"""

from __future__ import annotations

from typing import Any

from collector.lib.base import Collector
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_gke_clusters, gcp_logging_filter_extension
from collector.clouds.gcp.client_factory import GcpAccessDenied, GcpServiceNotEnabled

DEFAULT_WINDOW_DAYS = 7
GKE_AUDIT_LOG_FILTER = 'resource.type="k8s_cluster"'


def _audit_logging_enabled(cluster: dict[str, Any]) -> bool:
    lc = cluster.get("loggingConfig") or {}
    cc = lc.get("componentConfig") or {}
    components = list(cc.get("enableComponents") or [])
    if "APISERVER" in components:
        return True
    ls = str(cluster.get("loggingService") or "").strip()
    return bool(ls) and "none" not in ls.lower()


class GkeAuditCollector(Collector):
    name = "gke_audit"
    priority = 2
    description = "GKE Kubernetes API-server audit logs from Cloud Logging + cluster posture."
    required_actions = (
        "container.clusters.list",
        "logging.logEntries.list",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=DEFAULT_WINDOW_DAYS)
        cap = self.max_records(MAX_RECORDS)

        clusters = filter_gke_clusters(self._discover_clusters(cf, gaps), params)
        if not clusters:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("gke_audit", GapReason.NOT_PRESENT, "No GKE clusters in scope.")],
                notes="No GKE clusters found.",
            )

        audited = [c for c in clusters if c["audit_enabled"]]
        unaudited = [c for c in clusters if not c["audit_enabled"]]
        if unaudited:
            names = ", ".join(c["name"] for c in unaudited[:10])
            gaps.append(
                (
                    "gke_audit",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"API-server logging disabled on {len(unaudited)}/{len(clusters)} "
                    f"cluster(s): {names}.",
                )
            )

        scoped = gcp_logging_filter_extension(params)
        records: list[dict] = []
        per_cluster: list[dict] = []
        for cluster in audited:
            cluster_filter = self._cluster_filter(cluster, scoped)
            self._log(f"Reading audit logs for cluster {cluster['name']}…")
            before = len(records)
            try:
                for entry in cf.list_log_entries(
                    cluster["project_id"],
                    log_filter=cluster_filter,
                    start=start,
                    end=end,
                    max_records=cap - len(records) if len(records) < cap else 0,
                ):
                    tagged = dict(entry)
                    tagged["_ventra_cluster"] = cluster["name"]
                    tagged["_ventra_location"] = cluster["location"]
                    tagged["_ventra_project_id"] = cluster["project_id"]
                    records.append(tagged)
                    if len(records) >= cap:
                        break
            except GcpAccessDenied as exc:
                gaps.append(
                    ("gke_audit", GapReason.ACCESS_DENIED, f"{cluster['name']}: {exc.message}")
                )
            except GcpServiceNotEnabled as exc:
                gaps.append(
                    ("gke_audit", GapReason.SERVICE_NOT_ENABLED, f"{cluster['name']}: {exc.message}")
                )
            per_cluster.append({**cluster, "records": len(records) - before})

        if len(records) >= cap:
            self.append_truncation_gap(
                gaps,
                "gke_audit",
                cap,
                f"Truncated at {cap:,} records; narrow the window or use enterprise profile.",
            )

        config = {
            "clusters": clusters,
            "audit_enabled_count": len(audited),
            "audit_disabled_count": len(unaudited),
            "collection": per_cluster,
            "log_filter": GKE_AUDIT_LOG_FILTER,
            "window": {"since": start.isoformat(), "until": end.isoformat()},
            "artifact_parameters": params,
        }
        files = [self.write_json(config, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta(
            {
                "source": self.name,
                "records": len(records),
                "clusters": len(clusters),
                "audit_enabled": len(audited),
                "window": {"since": start.isoformat(), "until": end.isoformat()},
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif audited:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(("gke_audit", GapReason.NOT_PRESENT, "No audit events in window."))
        else:
            status = SourceStatus.EMPTY

        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} audit event(s) from "
            f"{len(audited)}/{len(clusters)} cluster(s) with API-server logging.",
        )

    def _discover_clusters(self, cf, gaps) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for project_id in self.ctx.project_ids:
            try:
                found = cf.list_gke_clusters(project_id)
            except GcpAccessDenied as exc:
                gaps.append(("gke_audit", GapReason.ACCESS_DENIED, f"{project_id}: {exc.message}"))
                continue
            except GcpServiceNotEnabled:
                continue
            for cluster in found:
                name = str(cluster.get("name") or "")
                location = str(cluster.get("location") or "")
                out.append(
                    {
                        "name": name,
                        "id": str(cluster.get("id") or cluster.get("selfLink") or ""),
                        "project_id": project_id,
                        "location": location,
                        "status": str(cluster.get("status") or ""),
                        "current_master_version": str(cluster.get("currentMasterVersion") or ""),
                        "audit_enabled": _audit_logging_enabled(cluster),
                    }
                )
        return out

    @staticmethod
    def _cluster_filter(cluster: dict[str, Any], scoped: str) -> str:
        name = cluster.get("name") or ""
        location = cluster.get("location") or ""
        parts = [
            GKE_AUDIT_LOG_FILTER,
            f'resource.labels.cluster_name="{name}"',
            f'resource.labels.location="{location}"',
        ]
        if scoped:
            parts.append(scoped)
        return " AND ".join(parts)
