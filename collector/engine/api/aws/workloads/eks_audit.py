"""EKS audit-log collector.

The Kubernetes API-server audit log is the only record of in-cluster activity — who exec'd
into a pod, read a secret, or created a privileged binding. None of that reaches CloudTrail.
This collector inventories EKS clusters, records which have audit logging enabled (shipped
to CloudWatch group ``/aws/eks/<cluster>/cluster``), pulls the audit events for the case
window, and records clusters WITHOUT audit logging as gaps.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled
from ..common.cw_logs import collect_cw_log_events

DEFAULT_WINDOW_DAYS = 7
AUDIT_STREAM_PREFIX = "kube-apiserver-audit"


def _audit_enabled(cluster: dict[str, Any]) -> bool:
    for entry in ((cluster.get("logging") or {}).get("clusterLogging")) or []:
        if entry.get("enabled") and "audit" in (entry.get("types") or []):
            return True
    return False


class EksAuditCollector(Collector):
    name = "eks_audit"
    priority = 2
    description = "EKS Kubernetes API-server audit logs from CloudWatch + cluster posture."
    required_actions = (
        "eks:ListClusters",
        "eks:DescribeCluster",
        "logs:FilterLogEvents",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        window = self.ctx.time_window
        start = window.since or (datetime.now(UTC) - timedelta(days=DEFAULT_WINDOW_DAYS))
        end = window.until or datetime.now(UTC)

        clusters = self._discover_clusters(cf, gaps)
        if not clusters:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [("eks_audit", GapReason.NOT_PRESENT, "No EKS clusters in scope.")],
                notes="No EKS clusters found.",
            )

        audited = [c for c in clusters if c["audit_enabled"]]
        unaudited = [c for c in clusters if not c["audit_enabled"]]
        if unaudited:
            names = ", ".join(c["name"] for c in unaudited[:10])
            gaps.append(
                (
                    "eks_audit",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    f"Audit logging disabled on {len(unaudited)}/{len(clusters)} "
                    f"cluster(s): {names}.",
                )
            )

        records: list[dict] = []
        per_cluster: list[dict] = []
        for cluster in audited:
            group = f"/aws/eks/{cluster['name']}/cluster"
            self._log(f"Reading audit log for cluster {cluster['name']}…")
            events, stats = collect_cw_log_events(
                cf,
                cluster["region"],
                group,
                start,
                end,
                gaps,
                "eks_audit",
                stream_prefix=AUDIT_STREAM_PREFIX,
            )
            recs = []
            for ev in events:
                rec = self._parse_audit_event(ev)
                if rec is not None:
                    rec["_ventra_cluster"] = cluster["name"]
                    recs.append(rec)
            records.extend(recs)
            per_cluster.append(
                {**cluster, "log_group": group, "records": len(recs)}
            )

        config = {
            "clusters": clusters,
            "audit_enabled_count": len(audited),
            "audit_disabled_count": len(unaudited),
            "collection": per_cluster,
            "window": window.to_manifest(),
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
                "window": window.to_manifest(),
            }
        )

        if records:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        elif audited:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
            gaps.append(
                ("eks_audit", GapReason.NOT_PRESENT, "No audit events in window.")
            )
        else:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} audit event(s) from "
            f"{len(audited)}/{len(clusters)} cluster(s) with audit logging.",
        )

    def _discover_clusters(self, cf, gaps) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for region in self.ctx.regions:
            try:
                names = list(cf.paginate("eks", region, "list_clusters", "clusters"))
            except AccessDenied as exc:
                gaps.append(("eks_audit", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except (ServiceNotEnabled, ClientError):
                continue
            for name in names:
                try:
                    cluster = cf.call("eks", region, "describe_cluster", name=name).get(
                        "cluster", {}
                    )
                except (AccessDenied, ServiceNotEnabled, ClientError) as exc:
                    gaps.append(("eks_audit", GapReason.COLLECTOR_ERROR, f"{name}: {exc}"))
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": cluster.get("arn", ""),
                        "region": region,
                        "version": cluster.get("version", ""),
                        "audit_enabled": _audit_enabled(cluster),
                    }
                )
        return out

    @staticmethod
    def _parse_audit_event(ev: dict[str, Any]) -> dict[str, Any] | None:
        """A CloudWatch event whose ``message`` is one Kubernetes audit JSON document."""
        try:
            rec = json.loads(ev.get("message", ""))
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(rec, dict):
            return None
        rec["_ventra_region"] = ev.get("_ventra_region", "")
        rec["_ventra_log_group"] = ev.get("_ventra_log_group", "")
        return rec
