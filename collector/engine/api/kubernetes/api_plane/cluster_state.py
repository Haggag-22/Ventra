"""k8s_cluster_state — the full cluster object inventory.

Collects the workload, identity, network, and admission objects across **all** namespaces
(kube-system included — attackers hide there). Secrets are captured as metadata only, never
their values. Derives ``suspicious_pods``: the container-escape-shaped pods an analyst should
look at first.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeNotFound
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import param_strings

from ..common.analysis import suspicious_pod_findings

# Registries considered trusted by default; extend per-engagement via the
# ``trusted_registries`` artifact parameter.
_DEFAULT_TRUSTED = (
    "registry.k8s.io",
    "k8s.gcr.io",
    "gcr.io/google-containers",
    "quay.io/coreos",
)


class ClusterStateCollector(Collector):
    name = "k8s_cluster_state"
    priority = 1
    plane = "api"
    description = "All-namespace inventory of workloads, identity, network and admission objects."
    required_actions = (
        "get pods", "list pods",
        "list deployments", "list daemonsets", "list statefulsets", "list replicasets",
        "list jobs", "list cronjobs",
        "list serviceaccounts", "list secrets", "list configmaps",
        "list services", "list ingresses", "list networkpolicies",
        "list nodes", "list namespaces",
        "list customresourcedefinitions",
        "list mutatingwebhookconfigurations", "list validatingwebhookconfigurations",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        files = []
        counts: dict[str, int] = {}

        kinds: dict[str, Callable[[], list[dict[str, Any]]]] = {
            "pods": cf.list_pods,
            "deployments": cf.list_deployments,
            "daemonsets": cf.list_daemon_sets,
            "statefulsets": cf.list_stateful_sets,
            "replicasets": cf.list_replica_sets,
            "jobs": cf.list_jobs,
            "cronjobs": cf.list_cron_jobs,
            "serviceaccounts": cf.list_service_accounts,
            "secrets": cf.list_secrets_metadata,
            "configmaps": cf.list_config_maps,
            "services": cf.list_services,
            "ingresses": cf.list_ingresses,
            "networkpolicies": cf.list_network_policies,
            "nodes": cf.list_nodes,
            "namespaces": cf.list_namespaces,
            "customresourcedefinitions": cf.list_crds,
            "mutatingwebhookconfigurations": cf.list_mutating_webhooks,
            "validatingwebhookconfigurations": cf.list_validating_webhooks,
        }

        collected: dict[str, list[dict[str, Any]]] = {}
        for kind, fn in kinds.items():
            rows = self._safe_list(kind, fn, gaps)
            if rows is None:
                continue
            collected[kind] = rows
            counts[kind] = len(rows)
            if rows:
                files.append(self.write_jsonl(rows, f"{kind}.jsonl.gz"))

        suspicious = self._suspicious_pods(collected.get("pods", []))
        if suspicious:
            files.append(self.write_json(suspicious, "suspicious_pods.json"))

        # High-value: mutating webhooks can silently inject containers cluster-wide. We keep
        # them called out in config (not as a gap) so the analyst reviews every one.
        webhooks = collected.get("mutatingwebhookconfigurations", [])

        config = {
            "counts": counts,
            "suspicious_pod_count": len(suspicious),
            "mutating_webhooks": [_wh_name(w) for w in webhooks],
            "trusted_registries": self._trusted_registries(),
        }
        files.append(self.write_json(config, "config.json"))
        self.write_meta(
            {"source": self.name, "counts": counts, "suspicious_pods": len(suspicious)}
        )

        total = sum(counts.values())
        if total == 0:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
        else:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=total,
            gaps=gaps,
            notes=f"{total} object(s) across {len(counts)} kind(s); "
            f"{len(suspicious)} suspicious pod(s).",
        )

    def _safe_list(
        self,
        kind: str,
        fn: Callable[[], list[dict[str, Any]]],
        gaps: list[tuple[str, GapReason, str]],
    ) -> list[dict[str, Any]] | None:
        """List one kind, turning a denial/absence into a gap and returning None."""
        try:
            rows = fn()
        except KubeAccessDenied as exc:
            gaps.append((self.name, GapReason.ACCESS_DENIED, f"{kind}: {exc.message}"))
            return None
        except KubeNotFound as exc:
            gaps.append((self.name, GapReason.NOT_PRESENT, f"{kind}: {exc.message}"))
            return None
        except Exception as exc:  # noqa: BLE001 - one kind failing must not abort the rest
            gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"{kind}: {exc}"))
            return None
        for row in rows:
            row["_ventra_cluster"] = self.ctx.account_id
        return rows

    def _suspicious_pods(self, pods: list[dict[str, Any]]) -> list[dict[str, Any]]:
        trusted = self._trusted_registries()
        out: list[dict[str, Any]] = []
        for pod in pods:
            findings = suspicious_pod_findings(pod, trusted_registries=trusted)
            if findings:
                out.append({"pod": findings[0], "findings": findings[1:]})
        return out

    def _trusted_registries(self) -> list[str]:
        extra = param_strings(self.artifact_params(), "trusted_registries")
        return list(_DEFAULT_TRUSTED) + extra


def _wh_name(webhook: dict[str, Any]) -> str:
    meta = webhook.get("metadata") or {}
    return str(meta.get("name", ""))
