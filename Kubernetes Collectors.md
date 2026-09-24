### Full Source Table

| Category               | Source                              | Primary Location                                                                  | Fallback / Alt                                                                         | Access         |
| ---------------------- | ----------------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | -------------- |
| **Control Plane**      | API Server Audit Log                | `--audit-log-path` (check apiserver flags)                                        | `/var/log/kube-apiserver-audit.log`, or `--audit-webhook-config-file` if external sink | Node FS        |
|                        | kube-apiserver logs                 | `/var/log/pods/kube-system_kube-apiserver-*/...` (static pod)                     | `journalctl` / `crictl logs` if systemd-run                                            | Node FS        |
|                        | kube-controller-manager logs        | `/var/log/pods/kube-system_kube-controller-manager-*/...`                         | same as above                                                                          | Node FS        |
|                        | kube-scheduler logs                 | `/var/log/pods/kube-system_kube-scheduler-*/...`                                  | same as above                                                                          | Node FS        |
|                        | etcd                                | `/var/lib/etcd` + `etcdctl snapshot save` (certs at `/etc/kubernetes/pki/etcd/*`) | —                                                                                      | Node FS        |
| **Node/System/App**    | Kubelet logs                        | `journalctl -u kubelet`                                                           | `/var/log/kubelet.log` if `--log-file` set                                             | Node FS        |
|                        | Container runtime logs              | `journalctl -u containerd` / `-u crio`                                            | `/var/log/containerd.log` (if configured), `crictl logs <id>` (live)                   | Node FS        |
|                        | Application logs                    | `kubectl logs <pod> -n <ns>` (while pod exists)                                   | `/var/log/pods/<ns>_<pod>_<uid>/<container>/*.log` if deleted                          | API or Node FS |
| **API Objects (live)** | Kubernetes Events                   | `GET /api/v1/events`, `GET /apis/events.k8s.io/v1/events`                         | `kubectl get events -A --sort-by=.lastTimestamp`                                       | API only       |
|                        | Admission webhook logs (if present) | `kubectl logs -n <ns> <webhook-pod>` (OPA/Gatekeeper, Kyverno, custom)            | —                                                                                      | API only       |


### Distribution note

The table above describes a **kubeadm** node. k3s, RKE2 and microk8s put the same evidence
somewhere else, and k3s has no static pods or etcd at all. See the **Distribution Matrix**
in `k8s-onprem-collector-build-spec.md` for the per-distro paths, units and datastores the
node-plane collectors fall back to, and for what each collector does on a worker or a managed
control plane.

### New: Inventory / Environment Snapshot Collector

This captures **current state**, not log history — your baseline for diffing and for spotting things that logs alone won't show clearly (e.g. "here is every ClusterRoleBinding that exists right now").

|Snapshot|What to capture|API call / method|
|---|---|---|
|**Cluster info**|Version, build date, platform|`GET /version`|
|**Nodes**|All nodes, labels, taints, conditions, kubelet version, OS/kernel version|`GET /api/v1/nodes`|
|**Namespaces**|Full list, labels, annotations|`GET /api/v1/namespaces`|
|**Workloads**|All Pods, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs — flag `privileged`, `hostPID`, `hostNetwork`, `hostPath`, `runAsUser: 0`, non-standard images/registries|`GET /api/v1/pods`, `apps/v1/{deployments,daemonsets,statefulsets}`, `batch/v1/{jobs,cronjobs}` (all namespaces)|
|**RBAC**|All Roles, ClusterRoles, RoleBindings, ClusterRoleBindings — especially bindings to `system:anonymous`, `system:unauthenticated`, or wildcard (`*`) verbs/resources|`rbac.authorization.k8s.io/v1/*`|
|**ServiceAccounts**|All SAs + their associated Secrets/tokens, `automountServiceAccountToken` settings|`GET /api/v1/serviceaccounts`|
|**Secrets (metadata only by default)**|Names, types, namespaces, owner references — avoid dumping values unless explicitly authorized|`GET /api/v1/secrets` (metadata-only list)|
|**ConfigMaps**|Names + data where relevant (watch for injected malicious config/env)|`GET /api/v1/configmaps`|
|**Webhooks**|All MutatingWebhookConfiguration / ValidatingWebhookConfiguration — check `clientConfig` URLs for anything pointing outside the cluster|`admissionregistration.k8s.io/v1/*`|
|**CRDs**|Full list — attackers sometimes register CRDs for stealthy persistence/state storage|`GET /apis/apiextensions.k8s.io/v1/customresourcedefinitions`|
|**PodSecurity/PSP/PSA state**|Namespace-level Pod Security Admission labels, or PSPs if an older cluster|`pod-security.kubernetes.io/*` labels on namespaces|
|**Network policies**|All NetworkPolicy objects|`networking.k8s.io/v1/networkpolicies`|
|**PVs / PVCs**|Storage inventory, `storageClassName`, `hostPath`-backed volumes flagged as high-risk|`GET /api/v1/persistentvolumes`, `persistentvolumeclaims`|
|**API resource discovery**|Full list of registered API groups/resources — reveals CRDs, aggregated APIs, or anything unusual installed|`GET /apis` (discovery)|
|**Images running cluster-wide**|Distinct list of `image` + `imageID` across all pod specs — cross-check against expected registries|Derived from Pods snapshot|
|**etcd member list & health**|Cluster topology, leader, member health|`etcdctl member list`, `endpoint heal`|