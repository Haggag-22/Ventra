/**
 * Where / how a collector gathers evidence (shown as "Collects from" in the Acquire info
 * dialog).
 *
 * Each entry says four things: which plane it runs on (Kubernetes API vs the node's own
 * filesystem and journal), where the evidence lives, how it is read, and which node it has to
 * run on when that matters. Kubernetes layouts differ per distribution, so the node-plane
 * entries name the kubeadm path and the k3s / RKE2 / microk8s fallbacks rather than implying
 * there is only one.
 *
 * House style: one paragraph, plain sentences, no em dashes.
 */

const KUBERNETES_SOURCE_HINTS: Record<string, string> = {
  k8s_apiserver_audit:
    "Node filesystem (control-plane or server node): the API audit log file, from --audit-log-path where the flags can be read, and otherwise from the documented defaults such as /var/log/kubernetes/audit/audit.log. Flags are resolved from a kubeadm or RKE2 static pod manifest, /etc/rancher/k3s/config.yaml, the k3s or rke2-server unit, or the microk8s args file, so no kubeadm manifest is required. Reads the active file plus its rotated and gzipped siblings.",
  k8s_audit_posture:
    "Node filesystem (control-plane or server node): kube-apiserver flags and the audit policy file, read from whichever source the distribution uses (kubeadm or RKE2 static pod manifest, k3s or RKE2 config, the server unit, or the microk8s args file). If no flag source is readable but an audit log file is already on disk, posture is reported from that file instead.",
  k8s_events:
    "Kubernetes API (kubeconfig only): Events across all namespaces from both core/v1 and events.k8s.io/v1, de-duplicated. The effective --event-ttl is read from the API server's real flags when a node is reachable, and assumed to be the 1h default when it is not.",
  k8s_cluster_state:
    "Kubernetes API (kubeconfig only): a live list of workloads, identity, network, storage and admission objects across every namespace, plus /version and API discovery. Secret values are never read.",
  k8s_rbac:
    "Kubernetes API (kubeconfig only): Roles, ClusterRoles, RoleBindings, ClusterRoleBindings and ServiceAccounts, listed and then resolved into the permissions each binding actually confers.",
  k8s_etcd:
    "Node filesystem (control-plane or server node): the cluster datastore and its posture. etcd under /var/lib/etcd with TLS in /etc/kubernetes/pki/etcd on kubeadm, embedded etcd under /var/lib/rancher/rke2 on RKE2, the sqlite datastore at /var/lib/rancher/k3s/server/db/state.db on a default k3s, or dqlite on microk8s. Reads flags, permissions, TLS material, etcdctl member health, and the etcd or merged server journal when no separate etcd log exists. The datastore itself is only captured when dump_db is set explicitly.",
  k8s_kubelet_logs:
    "Node filesystem (every node): journalctl -u kubelet, or /var/log/kubelet.log without systemd, or the distribution's node agent unit where the kubelet has no unit of its own (k3s-agent and k3s, rke2-agent, the microk8s kubelite daemon). Says which unit answered when it is shared with other collectors.",
  k8s_runtime_logs:
    "Node filesystem (every node): CRI logs and live state. Journal from journalctl -u containerd or -u crio, or from the distribution agent unit where containerd is embedded, plus live state from the CRI socket via crictl ps, images, pods and inspect. Embedded sockets such as /run/k3s/containerd/containerd.sock are probed alongside the standard path, so a missing runtime unit still yields live state.",
  k8s_cni_logs:
    "Node filesystem (every node): CNI plugin logs and flow evidence for Calico, Cilium, Flannel and Weave. The plugin is detected from every CNI config directory in use: /etc/cni/net.d, the k3s and RKE2 copies under /var/lib/rancher, and the microk8s args directory.",
  k8s_container_logs:
    "Node filesystem (every node): /var/log/pods, including the kubelet's rotated files and the logs of pods that no longer exist. Same layout on every distribution. The /var/log/containers symlinks are skipped because they point into the same tree.",
};

const SOURCE_HINTS: Record<string, Record<string, string>> = {
  kubernetes: KUBERNETES_SOURCE_HINTS,
};

/** Where / how this collector gathers evidence. */
export function collectorSourceHint(cloud: string, collector: string): string | null {
  const byCloud = SOURCE_HINTS[cloud.toLowerCase()];
  if (!byCloud) return null;
  return byCloud[collector] ?? null;
}
