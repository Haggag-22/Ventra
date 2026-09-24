"""k8s_cluster_state — the full cluster object inventory and environment snapshot.

Collects the workload, identity, network, storage, and admission objects across **all**
namespaces (kube-system included — attackers hide there), plus the environment snapshot an
analyst needs for baselining and diffing: cluster version, API discovery, Pod Security
Admission posture, and every distinct container image running cluster-wide.

Secrets are captured as metadata only, never their values. Derives ``suspicious_pods``: the
container-escape-shaped pods an analyst should look at first.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeNotFound
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import param_strings

from ..common.analysis import image_trusted, suspicious_pod_findings

# Registries considered trusted by default; extend per-engagement via the
# ``trusted_registries`` artifact parameter.
_DEFAULT_TRUSTED = (
    "registry.k8s.io",
    "k8s.gcr.io",
    "gcr.io/google-containers",
    "quay.io/coreos",
)

_PSA_LABEL_PREFIX = "pod-security.kubernetes.io/"


class ClusterStateCollector(Collector):
    name = "k8s_cluster_state"
    priority = 1
    plane = "api"
    description = "All-namespace inventory of workloads, identity, network, storage and admission."
    required_actions = (
        "get pods",
        "list pods",
        "list deployments",
        "list daemonsets",
        "list statefulsets",
        "list replicasets",
        "list jobs",
        "list cronjobs",
        "list serviceaccounts",
        "list secrets",
        "list configmaps",
        "list services",
        "list ingresses",
        "list networkpolicies",
        "list persistentvolumes",
        "list persistentvolumeclaims",
        "list nodes",
        "list namespaces",
        "list customresourcedefinitions",
        "list mutatingwebhookconfigurations",
        "list validatingwebhookconfigurations",
        "get /version",
        "get /apis",
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
            "persistentvolumes": cf.list_persistent_volumes,
            "persistentvolumeclaims": cf.list_persistent_volume_claims,
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

        # Derive the pod risk findings *before* writing, and stamp them onto the pod records
        # themselves. The evidence then carries its own verdict: an analyst reading
        # pods.jsonl.gz, and the ingester normalizing it, both see why a pod was flagged
        # without having to re-run the rules or cross-reference another file.
        suspicious = self._suspicious_pods(collected.get("pods", []))

        for kind, rows in collected.items():
            if rows:
                files.append(self.write_jsonl(rows, f"{kind}.jsonl.gz"))

        if suspicious:
            files.append(self.write_json(suspicious, "suspicious_pods.json"))

        # Distinct images + imageIDs cluster-wide — cross-check against expected registries.
        images = _distinct_images(collected.get("pods", []), self._trusted_registries())
        files.append(self.write_json(images, "images.json"))

        # hostPath-backed PersistentVolumes are node-filesystem access by another name.
        hostpath_pvs = _hostpath_pvs(collected.get("persistentvolumes", []))
        if hostpath_pvs:
            files.append(self.write_json(hostpath_pvs, "hostpath_volumes.json"))
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    f"{len(hostpath_pvs)} PersistentVolume(s) are hostPath-backed "
                    f"({', '.join(p['name'] for p in hostpath_pvs[:5])}) — any pod that binds "
                    "one reads and writes the node filesystem directly.",
                )
            )

        # ServiceAccounts: automount posture + which pods actually run as which SA.
        service_accounts = _service_account_usage(
            collected.get("serviceaccounts", []), collected.get("pods", [])
        )
        files.append(self.write_json(service_accounts, "service_accounts.json"))
        if service_accounts["automounting"]:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    f"{len(service_accounts['automounting'])} ServiceAccount(s) still automount "
                    "their token into every pod (automountServiceAccountToken is not false) — "
                    "any container compromise hands the attacker that SA's API credentials.",
                )
            )

        # Pod Security Admission posture (and PSPs if this is an older cluster).
        pod_security = self._pod_security(cf, collected.get("namespaces", []), gaps)
        files.append(self.write_json(pod_security, "pod_security.json"))

        # Cluster info + API discovery: the environment baseline.
        cluster_info = self._cluster_info(cf, gaps)
        discovery = self._api_discovery(cf, gaps)
        files.append(self.write_json({"cluster": cluster_info, "discovery": discovery}, "environment.json"))

        # High-value: mutating webhooks can silently inject containers cluster-wide. We keep
        # them called out in config (not as a gap) so the analyst reviews every one.
        webhooks = collected.get("mutatingwebhookconfigurations", [])

        config = {
            "counts": counts,
            "cluster": cluster_info,
            "suspicious_pod_count": len(suspicious),
            "mutating_webhooks": [_wh_name(w) for w in webhooks],
            "trusted_registries": self._trusted_registries(),
            "distinct_images": len(images.get("images", [])),
            "untrusted_images": len(images.get("untrusted", [])),
            "hostpath_persistentvolumes": len(hostpath_pvs),
            "service_accounts": {
                "total": len(service_accounts["accounts"]),
                "automounting": len(service_accounts["automounting"]),
            },
            "pod_security": {
                "namespaces_without_psa": len(pod_security.get("unlabelled_namespaces", [])),
                "psp_api_present": pod_security.get("psp_api_present"),
                "psp_count": len(pod_security.get("podsecuritypolicies", [])),
            },
            "api_group_versions": len(discovery.get("group_versions", [])),
        }
        files.append(self.write_json(config, "config.json"))
        self.write_meta({"source": self.name, "counts": counts, "suspicious_pods": len(suspicious)})

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
            f"{len(suspicious)} suspicious pod(s); "
            f"{len(images.get('images', []))} distinct image(s).",
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
            # The API returns list items without ``kind`` populated, so stamp it: the record
            # has to be self-describing for the ingester to normalize a mixed source.
            row["_ventra_kind"] = kind
        return rows

    # -- environment snapshot -------------------------------------------------------------

    def _cluster_info(self, cf: Any, gaps: list[tuple[str, GapReason, str]]) -> dict[str, Any]:
        """``GET /version`` — version, build date, platform."""
        fn = getattr(cf, "cluster_version", None)
        if fn is None:
            return {"determined": False, "reason": "client does not expose /version"}
        try:
            info = fn() or {}
        except KubeAccessDenied as exc:
            gaps.append((self.name, GapReason.ACCESS_DENIED, f"/version: {exc.message}"))
            return {"determined": False, "reason": exc.message}
        except Exception as exc:  # noqa: BLE001
            gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"/version: {exc}"))
            return {"determined": False, "reason": str(exc)}
        return {"determined": True, **{str(k): v for k, v in dict(info).items()}}

    def _api_discovery(self, cf: Any, gaps: list[tuple[str, GapReason, str]]) -> dict[str, Any]:
        """``GET /apis`` discovery — reveals CRDs, aggregated APIs, anything unusual installed."""
        fn = getattr(cf, "api_resources", None)
        if fn is None:
            return {"determined": False, "group_versions": []}
        try:
            out = fn() or {}
        except KubeAccessDenied as exc:
            gaps.append((self.name, GapReason.ACCESS_DENIED, f"/apis: {exc.message}"))
            return {"determined": False, "group_versions": []}
        except Exception as exc:  # noqa: BLE001
            gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"/apis: {exc}"))
            return {"determined": False, "group_versions": []}
        out["determined"] = True
        return out

    def _pod_security(
        self,
        cf: Any,
        namespaces: list[dict[str, Any]],
        gaps: list[tuple[str, GapReason, str]],
    ) -> dict[str, Any]:
        """PSA labels per namespace, plus PSPs when the cluster still serves that API."""
        out: dict[str, Any] = {
            "namespaces": [],
            "unlabelled_namespaces": [],
            "privileged_namespaces": [],
            "psp_api_present": False,
            "podsecuritypolicies": [],
        }
        for ns in namespaces:
            meta = ns.get("metadata") or {}
            name = str(meta.get("name", ""))
            labels = {
                k: v for k, v in (meta.get("labels") or {}).items() if str(k).startswith(_PSA_LABEL_PREFIX)
            }
            out["namespaces"].append({"namespace": name, "pod_security_labels": labels})
            if not labels:
                out["unlabelled_namespaces"].append(name)
            elif str(labels.get(f"{_PSA_LABEL_PREFIX}enforce", "")).lower() == "privileged":
                out["privileged_namespaces"].append(name)

        if out["privileged_namespaces"]:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    "Namespace(s) enforce the 'privileged' Pod Security Admission level: "
                    + ", ".join(out["privileged_namespaces"])
                    + " — privileged, hostPath, and hostPID pods are admitted there without "
                    "restriction.",
                )
            )

        fn = getattr(cf, "list_pod_security_policies", None)
        if fn is not None:
            try:
                psps = fn() or []
            except KubeNotFound:
                # PSP was removed in v1.25 — absence is the expected modern case, not a gap.
                psps = []
            except KubeAccessDenied as exc:
                gaps.append((self.name, GapReason.ACCESS_DENIED, f"podsecuritypolicies: {exc.message}"))
                psps = []
            except Exception:  # noqa: BLE001
                psps = []
            else:
                out["psp_api_present"] = True
            out["podsecuritypolicies"] = psps
        return out

    # -- derived signals ------------------------------------------------------------------

    def _suspicious_pods(self, pods: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Flag container-escape-shaped pods, stamping each verdict onto the pod record."""
        trusted = self._trusted_registries()
        out: list[dict[str, Any]] = []
        for pod in pods:
            findings = suspicious_pod_findings(pod, trusted_registries=trusted)
            if not findings:
                continue
            pod["_ventra_suspicious"] = findings[1:]
            out.append({"pod": findings[0], "findings": findings[1:]})
        return out

    def _trusted_registries(self) -> list[str]:
        extra = param_strings(self.artifact_params(), "trusted_registries")
        return list(_DEFAULT_TRUSTED) + extra


def _distinct_images(pods: list[dict[str, Any]], trusted: list[str]) -> dict[str, Any]:
    """Every distinct ``image`` + ``imageID`` running cluster-wide, with where it runs.

    The spec's ``image`` is what was asked for; the status' ``imageID`` is the digest that was
    actually pulled. A mismatch between the two across pods running the same tag is how a
    re-pushed ``:latest`` tag shows up.
    """
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for pod in pods:
        meta = pod.get("metadata") or {}
        where = f"{meta.get('namespace', '')}/{meta.get('name', '')}"
        spec = pod.get("spec") or {}
        status = pod.get("status") or {}

        # imageID lives on the status, keyed by container name.
        ids: dict[str, str] = {}
        for key in (
            "container_statuses",
            "containerStatuses",
            "init_container_statuses",
            "initContainerStatuses",
            "ephemeral_container_statuses",
            "ephemeralContainerStatuses",
        ):
            for cs in status.get(key) or []:
                if isinstance(cs, dict) and cs.get("name"):
                    ids[str(cs["name"])] = str(cs.get("image_id") or cs.get("imageID") or "")

        for key in (
            "containers",
            "init_containers",
            "initContainers",
            "ephemeral_containers",
            "ephemeralContainers",
        ):
            for container in spec.get(key) or []:
                if not isinstance(container, dict):
                    continue
                image = str(container.get("image", ""))
                if not image:
                    continue
                image_id = ids.get(str(container.get("name", "")), "")
                entry = seen.setdefault(
                    (image, image_id),
                    {
                        "image": image,
                        "imageID": image_id,
                        "trusted": image_trusted(image, trusted) if trusted else True,
                        "pods": [],
                    },
                )
                if where not in entry["pods"]:
                    entry["pods"].append(where)

    images = sorted(seen.values(), key=lambda e: (e["image"], e["imageID"]))
    return {
        "images": images,
        "untrusted": [e for e in images if not e["trusted"]],
    }


def _service_account_usage(
    service_accounts: list[dict[str, Any]], pods: list[dict[str, Any]]
) -> dict[str, Any]:
    """Per-ServiceAccount automount setting, bound secrets, and the pods running as it.

    ``automountServiceAccountToken`` defaults to **true** when unset, so an absent field is
    reported as automounting — that is what the API server actually does.
    """
    pods_by_sa: dict[tuple[str, str], list[str]] = {}
    for pod in pods:
        meta = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        ns = str(meta.get("namespace", ""))
        name = str(meta.get("name", ""))
        sa = str(
            spec.get("service_account_name")
            or spec.get("serviceAccountName")
            or spec.get("service_account")
            or "default"
        )
        pods_by_sa.setdefault((ns, sa), []).append(name)

    accounts: list[dict[str, Any]] = []
    automounting: list[str] = []
    for sa in service_accounts:
        meta = sa.get("metadata") or {}
        ns = str(meta.get("namespace", ""))
        name = str(meta.get("name", ""))
        raw = sa.get("automount_service_account_token")
        if raw is None:
            raw = sa.get("automountServiceAccountToken")
        automount = True if raw is None else bool(raw)
        entry = {
            "namespace": ns,
            "name": name,
            "automount_service_account_token": automount,
            "automount_explicit": raw is not None,
            "secrets": [str((sec or {}).get("name", "")) for sec in (sa.get("secrets") or [])],
            "image_pull_secrets": [
                str((sec or {}).get("name", ""))
                for sec in (sa.get("image_pull_secrets") or sa.get("imagePullSecrets") or [])
            ],
            "pods": sorted(pods_by_sa.get((ns, name), [])),
        }
        accounts.append(entry)
        if automount:
            automounting.append(f"{ns}/{name}")
    return {"accounts": accounts, "automounting": sorted(automounting)}


def _hostpath_pvs(pvs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """PersistentVolumes backed by a node hostPath — high-risk storage."""
    out: list[dict[str, Any]] = []
    for pv in pvs:
        spec = pv.get("spec") or {}
        host_path = spec.get("host_path") or spec.get("hostPath") or {}
        if not host_path:
            continue
        meta = pv.get("metadata") or {}
        out.append(
            {
                "name": str(meta.get("name", "")),
                "path": str(host_path.get("path", "")),
                "storageClassName": str(spec.get("storage_class_name") or spec.get("storageClassName") or ""),
                "claimRef": spec.get("claim_ref") or spec.get("claimRef") or {},
            }
        )
    return out


def _wh_name(webhook: dict[str, Any]) -> str:
    meta = webhook.get("metadata") or {}
    return str(meta.get("name", ""))
