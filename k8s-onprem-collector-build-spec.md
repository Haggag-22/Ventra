# Build Spec — On-Prem Kubernetes DFIR Collectors

> **Use this as the implementation prompt for the `kubernetes` platform.** It defines scope,
> architecture, the exact collector set, non-goals, RBAC, evidence-integrity rules, and
> acceptance criteria. Follow the existing collector conventions (`Collector` base class,
> `SourceResult` / `SourceStatus` / `GapReason`, artifact YAML, param definitions, catalog
> labels) — do not invent a parallel framework.

---

## 1. Scope and Framing

### What we are building
A **self-managed / on-premises Kubernetes** evidence-collection engine, sitting alongside the
existing cloud engines (`aws`, `azure`, `gcp`). This is the `kubernetes` platform already
stubbed in `CASE_PLATFORMS`.

### The core distinction from the cloud engines
The existing `eks_audit`, `gke_audit`, and `aks_audit` collectors are **cloud-side**: they pull
control-plane audit logs out of CloudWatch / Cloud Logging / Storage diagnostics, because on a
managed cluster the control plane is a black box you cannot log into.

**On-prem, we own every node — including the control-plane nodes.** That means:
- The API-server audit log is a **file on disk**, not a cloud log stream.
- etcd, kube-scheduler, and kube-controller-manager logs are **directly readable**.
- We can run privileged workloads on nodes, read the container runtime state, and use the
  **kubelet CRIU checkpoint API** to capture live container memory.

None of that is possible on EKS/GKE/AKS. This engine exists specifically to exploit it.

### Two collection planes
Every collector belongs to exactly one:

| Plane | Mechanism | Runs as |
|---|---|---|
| **API plane** | Kubernetes API server (client-go / Python `kubernetes` client) | Out-of-cluster, using a kubeconfig |
| **Node plane** | Reads node filesystem, systemd journal, CRI socket, kubelet endpoint | In-cluster, as a privileged DaemonSet or on-demand Job |

Do not mix planes inside a single collector. It makes RBAC, failure modes, and gap reporting
incoherent.

---

## 2. Architecture

### 2.1 API-plane collectors
- Authenticate from a kubeconfig supplied at case setup (path or inline, stored as a case secret).
- Use a **read-only ClusterRole**. Do not require cluster-admin. Ship the ClusterRole YAML in
  `resources/kubernetes/rbac/ventra-collector-readonly.yaml` and make the tool verify its own
  permissions with a `SelfSubjectAccessReview` before collecting.
- If a permission is missing, emit `GapReason.ACCESS_DENIED` for that source and continue.
  **Never abort the whole run because one verb is denied.**

### 2.2 Node-plane collectors
- Ship a **collector image** and two deployment modes:
  - **DaemonSet** (`ventra-node-collector`) — sweeps every node.
  - **Job** (`ventra-node-collector-job`) — targeted at one node via `nodeName`, for
    single-pod/single-node deep dives. Model this on the `kube-forensics` Job-on-target-node
    pattern, but runtime-agnostic.
- The pod mounts, read-only wherever possible:
  - `/var/log` → container, pod, and component logs
  - `/var/lib/kubelet` → checkpoints, pod volumes
  - `/var/lib/containerd` (or `/var/lib/containers` for CRI-O) → overlay layers
  - `/run/containerd/containerd.sock` (or `/var/run/crio/crio.sock`) → CRI socket
  - `/etc/kubernetes` → static pod manifests, audit policy
  - Host journal (`/var/log/journal`, `/run/log/journal`)
- `hostPID: true` only where the collector genuinely needs the host process view. Everything
  else stays as unprivileged as it can be.
- **Runtime detection is mandatory and up front.** Detect containerd vs CRI-O (vs Docker on
  ancient clusters) once, and branch. Store the detected runtime + version in the run manifest.

### 2.3 Output
Same as the cloud engines: normalized records into the case store, a raw-evidence archive, and
per-source `SourceResult` with gaps. Add a `NodeContext` (node name, kernel, runtime, kubelet
version) to every node-plane record so an analyst can always trace a record back to its node.

---

## 3. The Collector Set

Priority `1` = collect first (most volatile or most important). Build in priority order.

### Priority 1 — API plane

#### `k8s_events` — Kubernetes Events
- **Why:** the single most perishable artifact in the cluster.
- **Critical constraint:** the API server garbage-collects Events after `--event-ttl`, which
  **defaults to `1h0m0s`**. If the incident is more than an hour old, this data is simply gone.
- **Collect:** all Events, all namespaces, `core/v1` and `events.k8s.io/v1`.
- **Required verbs:** `get`, `list`, `watch` on `events`.
- **Gap:** if the collection window start predates `now - event_ttl`, emit
  `GapReason.RETENTION_EXPIRED` with an explicit note. Read the actual `--event-ttl` from the
  kube-apiserver static pod manifest when the node plane is available; otherwise assume 1h and
  say so.
- **Flag in analysis:** unexpected image pulls, `Failed`/`BackOff`, OOMKills, evictions,
  `FailedMount` on hostPath volumes.

#### `k8s_audit_posture` — Audit logging posture
- **Why:** the most common finding in a Kubernetes IR is *"there is no audit log."* Report that
  as a first-class result, not a silent absence.
- **Collect:** from `/etc/kubernetes/manifests/kube-apiserver.yaml` (node plane) or by probing:
  whether `--audit-log-path` and `--audit-policy-file` are set; the policy file contents; the
  configured `--audit-log-maxage` / `--audit-log-maxbackup` / `--audit-log-maxsize`; whether a
  webhook backend is configured.
- **Gap:** if audit logging is off → `GapReason.LOGGING_NOT_CONFIGURED`, severity **critical**.
  This must surface prominently in the report, same as the `audit_enabled` check in
  `eks_audit` / `gke_audit` / `aks_audit`.
- **Also flag:** an audit policy that only logs at `Metadata` level for sensitive resources, or
  one that omits `secrets` / `pods/exec` — a policy that exists but is useless is a gap too.

#### `k8s_cluster_state` — Cluster object inventory
- **Collect** (all namespaces, skip nothing by default — an attacker will hide in `kube-system`):
  - Pods (full spec + status), Deployments, DaemonSets, StatefulSets, ReplicaSets
  - **CronJobs and Jobs** (classic persistence mechanism)
  - ServiceAccounts, and which pods mount which
  - Secrets — **metadata only, never the values**
  - ConfigMaps
  - Services, Ingresses, NetworkPolicies
  - Nodes, Namespaces
  - CRDs and custom resources (attackers abuse operators)
  - MutatingWebhookConfigurations / ValidatingWebhookConfigurations — **high value**, a rogue
    mutating webhook silently injects containers cluster-wide
- **Required verbs:** `get`, `list` on the above.
- **Derived signal — `suspicious_pods`:** flag pods that are `privileged: true`, have
  `hostNetwork` / `hostPID` / `hostIPC`, mount a writable `hostPath` (especially `/`,
  `/var/run/docker.sock`, `/var/lib/kubelet`), request dangerous capabilities
  (`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`), or run an image from an unexpected registry.

#### `k8s_rbac` — RBAC snapshot
- **Collect:** Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, plus ServiceAccounts.
- **Derived signal:** compute effective permissions and flag any subject that can
  `create pods/exec`, `get secrets` cluster-wide, `escalate`/`bind` on roles, `impersonate`, or
  holds `cluster-admin`. Flag bindings to `system:anonymous` or `system:unauthenticated`.
- **Why:** privilege escalation via RBAC is the most common post-exploitation move, and the
  binding object itself is durable evidence.

---

### Priority 1 — Node plane

#### `k8s_apiserver_audit` — The API-server audit log **(the crown jewel)**
- **Why:** this is the only record of *who did what* inside the cluster. Nothing else shows
  `pods/exec`, secret reads, or RBAC changes.
- **Collect:** the file at `--audit-log-path` (commonly `/var/log/kubernetes/audit/audit.log`)
  plus its rotated siblings. Parse the JSON `audit.k8s.io/v1` Event objects.
- **Normalize into the timeline** with: `user.username`, `user.groups`, `impersonatedUser`,
  `sourceIPs`, `verb`, `objectRef` (resource/namespace/name/subresource),
  `responseStatus.code`, `stage`, `requestReceivedTimestamp`, `auditID`.
- **Priority detections to build in:**
  - `objectRef.subresource == "exec"` or `"attach"` → someone got a shell in a container
  - `verb == "get"` on `secrets` → credential theft
  - `create`/`update` on `clusterrolebindings` / `rolebindings` → privilege escalation
  - `create` on `pods` with a privileged/hostPath spec → container escape setup
  - `delete` bursts → anti-forensics
  - anonymous or `system:unauthenticated` subjects doing anything at all
  - requests from `sourceIPs` outside the expected admin range
  - `create` on `pods/portforward`
- **Gap:** if the file does not exist → `GapReason.LOGGING_NOT_CONFIGURED`, and cross-link to
  `k8s_audit_posture`.

#### `k8s_container_logs` — Container logs from the node
- **Collect:** `/var/log/pods/<namespace>_<pod>_<uid>/<container>/*.log`
  (`/var/log/containers/*.log` are symlinks into this — follow them, don't collect twice).
- **More complete than the API** for rotated logs and for pods that no longer exist.

#### `k8s_container_fs` — Container filesystem changes
- **Why:** dropped binaries, cryptominers, webshells — the actual malware.
- **Collect, per target container:**
  - The **OverlayFS upper (RW) layer** — every file the container created or modified since it
    started from its image. Resolve the path via `crictl inspect <id>` → `.info.runtimeSpec` /
    the runtime's `GraphDriver`-equivalent. Do **not** hardcode paths; containerd and CRI-O lay
    out storage differently.
  - **In-container shell history**: `/root/.bash_history`, `/root/.ash_history`,
    `/home/*/.bash_history` (Alpine-based images use `ash`).
  - A **full filesystem export** (`crictl`/`ctr` export, or a tar of the merged dir) for the
    containers implicated in the incident — not for every container in the cluster.
- **Hash every extracted file (sha256)** and record the hash in the manifest at collection time.
- **Critical caveat:** containers run with `--rm`-equivalent semantics, and evicted/restarted
  pods, lose all of this on exit. This is why it is priority 1.

---

### Priority 2 — Node plane

#### `k8s_kubelet_logs`
- `journalctl -u kubelet` (or `/var/log/kubelet.log` on non-systemd nodes).
- Gives the node's own account of pod admission, image pulls, container start/stop, volume
  mounts. **Cross-check it against the API audit log** — a divergence between what the API server
  was asked to do and what the kubelet actually did is a strong tampering signal.

#### `k8s_runtime_logs`
- `journalctl -u containerd` / `journalctl -u crio`.
- Image pulls (including from unexpected registries), container lifecycle, CRI errors.
- Also snapshot live runtime state: `crictl ps -a`, `crictl images`, `crictl pods`,
  `crictl inspect` for each container.

#### `k8s_etcd` — **on-prem exclusive**
- etcd logs: `/var/log/pods/kube-system_etcd-*/` or `journalctl -u etcd`.
- Collect etcd's **config and TLS posture**: is client cert auth enforced? Is it listening on a
  non-loopback address? Is it unencrypted at rest?
- **Do not dump the etcd database contents by default.** It contains every Secret in the cluster
  in plaintext (unless encryption-at-rest is on). Make it an explicit, separately-confirmed
  parameter, and treat any resulting artifact as maximum-sensitivity.
- **Flag hard:** any client connection to etcd from anything other than the API server. Direct
  etcd access is total cluster compromise.

#### `k8s_node_os` — Host-level Linux forensics
- `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL), `/var/log/syslog` / `/var/log/messages`,
  `journalctl -k` (kernel).
- Also: `/etc/passwd`, `/etc/shadow` metadata, cron (`/etc/cron*`, user crontabs), systemd units
  (persistence), SSH `authorized_keys`, `last`/`wtmp`/`btmp`.
- **Why:** if the attacker escaped the container, this is where you see it.

#### `k8s_cni_logs`
- Detect the plugin, then collect accordingly: Calico (`/var/log/calico/`), Cilium
  (`cilium-dbg` / Hubble flows if present), Flannel, Weave.
- Also collect the effective NetworkPolicy set and, where the plugin supports it, **flow logs**
  — the primary evidence for lateral movement and exfiltration.

#### `k8s_runtime_security`
- If Falco / Tetragon / another eBPF runtime sensor is deployed as a DaemonSet, collect its
  alerts and its ruleset.
- This is often the **best evidence available** — syscall-level detection of reverse shells,
  privilege escalation, and sensitive file reads that nothing else captures. Detect it, don't
  require it.

---

### Priority 3 — Node plane, advanced

#### `k8s_checkpoint` — Live container memory capture via CRIU
- **The single most powerful technique on-prem, and impossible on managed clusters.**
- **How:** POST to the kubelet on the target node:
  ```
  curl -X POST "https://localhost:10250/checkpoint/<namespace>/<pod>/<container>"
  ```
  The kubelet asks the CRI runtime, which invokes CRIU, which dumps the container's full
  process memory **without stopping it and without the container being aware**.
- **Feature gate:** `ContainerCheckpoint` — **beta and enabled by default since Kubernetes
  v1.30**. Still pre-GA. On older clusters it must be explicitly enabled, and the runtime must
  support it (CRI-O needs `enable_criu_support = true`).
- **Output:** `/var/lib/kubelet/checkpoints/checkpoint-<pod>_<ns>-<container>-<timestamp>.tar`,
  containing:
  - `checkpoint/` — the CRIU image files (`pstree.img`, `core-*.img`, `pagemap-*.img`,
    `pages-*.img`, `reg-files.img`, …)
  - `rootfs-diff.tar` — files created/changed vs. the base image
  - `config.dump`, `spec.dump`, `bind.mounts`, `dump.log`, `stats-dump`
- **Analysis pipeline to build:** `checkpointctl inspect --files --ps-tree --metadata` for the
  overview; `crit show checkpoint/pstree.img` to decode CRIU protobuf images; string extraction;
  optional sandboxed restore under a standalone CRI-O for full dynamic analysis.
- **Build these guards, non-negotiable:**
  - **Capability probe first.** The endpoint returns HTTP 500 when the runtime doesn't implement
    checkpointing, or for containers using GPUs / InfiniBand (no CRIU plugin). Probe, and emit
    `GapReason.NOT_SUPPORTED` rather than failing the run.
  - **Treat the archive as a secret.** It contains *every memory page of every process* —
    which means plaintext credentials, private keys, and session tokens. Encrypt at rest,
    restrict access, log every read, and mark it maximum-sensitivity in the evidence manifest.
  - Never restore a checkpoint back into the production cluster.

---

## 3.1 Distribution Matrix

The collector set above was specified against **kubeadm**, where the control plane runs as
static pods under `/etc/kubernetes/manifests` and each component has its own log tree. That is
one layout among several, and the differences are not cosmetic: on k3s there is no static pod
directory, no per-component log tree, and no etcd. Node-plane collectors therefore resolve the
distribution once per run (`collector/engine/api/kubernetes/common/distro.py`) and work down an
ordered list of candidates, recording every path and unit they tried.

**Detection is filesystem-only and read-only.** It reads well-known directories and systemd
*unit files*; it never shells out to `systemctl`, so it works from a pod with the host mounted
read-only, and it is deterministic in tests.

### Where the control plane lives

| Family | Detected by | Control-plane logs | Static pod manifests | Datastore | Node agent (kubelet) |
|---|---|---|---|---|---|
| **kubeadm** | `/etc/kubernetes/manifests/kube-apiserver.yaml`, `admin.conf` | `/var/log/pods/kube-system_<component>-*`, else `journalctl -u kube-apiserver` (and per component), else `crictl logs` | `/etc/kubernetes/manifests` | etcd: `/var/lib/etcd`, TLS `/etc/kubernetes/pki/etcd` | `journalctl -u kubelet` |
| **k3s** | `/etc/rancher/k3s`, `/var/lib/rancher/k3s`, unit `k3s` / `k3s-agent` | `journalctl -u k3s` **only**. One process carries apiserver + scheduler + controller-manager | none (by design) | sqlite `/var/lib/rancher/k3s/server/db/state.db`, or embedded etcd `.../db/etcd` | inside `k3s` (server) or `k3s-agent` (worker) |
| **RKE2** | `/etc/rancher/rke2`, `/var/lib/rancher/rke2`, unit `rke2-server` / `rke2-agent` | `journalctl -u rke2-server` | `/var/lib/rancher/rke2/agent/pod-manifests` | embedded etcd `/var/lib/rancher/rke2/server/db/etcd` | inside `rke2-agent` / `rke2-server` |
| **microk8s** | `/var/snap/microk8s` | `journalctl -u snap.microk8s.daemon-kubelite` | `/etc/kubernetes/manifests` if present | dqlite `/var/snap/microk8s/current/var/kubernetes/backend` | inside the kubelite daemon |
| **managed** (EKS / GKE / AKS worker) | no known layout found | none on the node | none | none | `journalctl -u kubelet` |

Other per-distro paths that matter: API-server flags come from
`/etc/rancher/{k3s,rke2}/config.yaml`, the server unit's `ExecStart` line, or
`/var/snap/microk8s/current/args/kube-apiserver` when there is no manifest to read; CNI config
lives under `/var/lib/rancher/<distro>/agent/etc/cni/net.d` on k3s and RKE2; containerd's
socket is `/run/k3s/containerd/containerd.sock` on k3s and RKE2 and
`/var/snap/microk8s/common/run/containerd.sock` on microk8s.

### Which collectors work where

`CP` = control-plane / server node only. `any` = every node. `api` = API plane, needs only a
kubeconfig and does not care about the distribution.

| Collector | Plane | Node | kubeadm | k3s | RKE2 | microk8s | managed worker |
|---|---|---|---|---|---|---|---|
| `k8s_events` | api | - | yes | yes | yes | yes | yes |
| `k8s_cluster_state` | api | - | yes | yes | yes | yes | yes |
| `k8s_rbac` | api | - | yes | yes | yes | yes | yes |
| `k8s_apiserver_audit` | node | CP | manifest flag | k3s config / defaults | RKE2 manifest / config | args file | gap |
| `k8s_audit_posture` | node | CP | manifest flags | config or log on disk | manifest or config | args file | gap |
| `k8s_etcd` | node | CP | etcd | sqlite or etcd (+ merged journal) | etcd (+ merged journal) | dqlite | gap |
| `k8s_kubelet_logs` | node | any | `kubelet` unit | `k3s` / `k3s-agent` | `rke2-agent` | kubelite | `kubelet` unit |
| `k8s_runtime_logs` | node | any | `containerd` unit + socket | socket, journal via `k3s` | socket, journal via `rke2-agent` | socket + kubelite | `containerd` unit + socket |
| `k8s_container_logs` | node | any | `/var/log/pods` | same | same | same | same |
| `k8s_cni_logs` | node | any | `/etc/cni/net.d` | rancher CNI dir | rancher CNI dir | snap args dir | `/etc/cni/net.d` |

"gap" means the collector records what it looked for and emits a `GapReason` with the reason.
It is never a crash and never a silent empty result: a worker simply has no control plane on it.

### What an operator should check manually

If a control-plane collector gaps, the fastest confirmations are:

* **kubeadm** - `ls /etc/kubernetes/manifests`, `journalctl -u kubelet | head`
* **k3s** - `systemctl status k3s`, `journalctl -u k3s | head`, `ls /var/lib/rancher/k3s/server/db`
* **RKE2** - `systemctl status rke2-server`, `ls /var/lib/rancher/rke2/agent/pod-manifests`
* **microk8s** - `microk8s status`, `cat /var/snap/microk8s/current/args/kube-apiserver`
* **any** - is the audit log actually on disk? `ls -l /var/log/kubernetes/audit/`

Each collector's `config.json` records the detected distribution, every candidate path and unit
it tried, and which one answered, so this can be reconstructed after the fact from the evidence
package alone.

---

## 4. What NOT to Build

| Don't | Why |
|---|---|
| **Anything `docker`-based** (`docker ps`, `docker inspect`, `docker diff`, `docker export`, `/var/lib/docker/...`) | Dockershim was removed in Kubernetes **v1.24**. Most published Kubernetes forensics content — including `kube-forensics` (last release 2020) and the widely-cited Sysdig DFIR walkthrough — is Docker-era and will simply not run on a modern cluster. **Use `crictl` / `ctr` against the CRI socket.** Support Docker only behind an explicit legacy flag, if at all. |
| **Re-collecting cloud control-plane audit logs** | Already covered by `eks_audit` / `gke_audit` / `aks_audit`. Do not duplicate. |
| **Assuming a fixed on-disk layout** | containerd, CRI-O, and Podman all store overlays and configs differently. Detect the runtime, then branch. Hardcoded paths are the #1 source of silent collection failure. |
| **`kubectl exec` for evidence collection** | It mutates the target: touches atimes, appends to shell history, appears in the process table, and lands in the audit log the attacker may be watching. Prefer passive API reads, node-plane filesystem access, and CRIU checkpointing — which the container cannot observe. Allow `exec` only as an explicitly-flagged last resort. |
| **Deleting the compromised pod** | Destroys all container filesystem and memory evidence. Containment must be **isolate, not destroy**: apply a deny-all `NetworkPolicy` (ingress + egress) scoped to a quarantine label, relabel the pod out of its Service selector, and `kubectl cordon` the node. The pod keeps running; it just can't talk to anything. |
| **Requiring cluster-admin for the API plane** | Ship a minimal read-only ClusterRole. Cluster-admin makes the tool itself a lateral-movement target and will get you blocked by security review. |
| **Dumping Secret values by default** | Collect Secret *metadata* (name, namespace, type, which pods mount it, creation timestamp) — not the payloads. Values only behind an explicit, separately-confirmed parameter. |
| **Dumping the etcd database by default** | Same reason, worse blast radius: it's every Secret in the cluster at once. |
| **Aborting the run on a single permission denial** | Emit the gap, continue. A partial collection is enormously more useful than nothing. |
| **Silently skipping `kube-system`** | KubeForenSys skips system namespaces by design; that's a defensible product choice but a **bad forensic default**. Attackers hide precisely there. Collect it, and let the analyst filter. |

---

## 5. RBAC and Privilege Requirements

### API plane — minimal read-only ClusterRole
Verbs `get`, `list`, `watch` on:
- `pods`, `pods/log`, `events`, `nodes`, `namespaces`, `serviceaccounts`, `configmaps`,
  `services`, `secrets` *(metadata only — enforce this in code, not just in RBAC)*
- `deployments`, `daemonsets`, `statefulsets`, `replicasets`, `jobs`, `cronjobs`
- `networkpolicies`, `ingresses`
- `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`
- `customresourcedefinitions`
- `mutatingwebhookconfigurations`, `validatingwebhookconfigurations`

Plus `create` on `selfsubjectaccessreviews` so the tool can pre-flight its own permissions.

### Node plane
Requires the ability to schedule a **privileged pod** with hostPath mounts (and `hostPID` for
some collectors) — effectively cluster-admin-equivalent, and it will be rejected by Pod Security
Admission under the `restricted` profile. Document this plainly. Ship a dedicated namespace with
a `privileged` PSA label and a dedicated ServiceAccount that is **created for the engagement and
deleted after**.

### Checkpoint
Cluster-admin plus node access — the kubelet checkpoint endpoint is reachable on
**localhost only**, which is precisely why it must run from a pod on the target node (or over SSH).

---

## 6. Evidence Integrity — Non-Negotiable

1. **Hash on collect.** sha256 of every artifact, computed at the moment of acquisition, written
   into a signed manifest alongside: collector name + version, node name, timestamp (UTC),
   operator identity, cluster identifier, and the source path or API endpoint.
2. **Snapshot, never mutate.** Read-only mounts. No writes to the target node. No `exec` into
   the target container unless explicitly authorized.
3. **Write-once storage.** Push evidence to an immutable/WORM bucket; never overwrite.
4. **Record what you could not get.** A gap is a finding. `GapReason.LOGGING_NOT_CONFIGURED` on
   the audit log is often the single most important line in the report.
5. **Classify sensitivity.** Checkpoint archives, etcd dumps, and Secret values are
   maximum-sensitivity; encrypt at rest and gate access.

---

## 7. Volatility — Collection Order

Collect strictly in this order. The tool should enforce it.

1. **Kubernetes Events** — *gone in 1 hour by default.* Nothing else is this urgent.
2. **Live container state** — running processes, sockets, and (if available) CRIU memory
   checkpoints of implicated containers.
3. **Ephemeral pod artifacts** — logs and filesystems of pods that may be restarted, evicted, or
   killed at any moment.
4. **Container filesystems and runtime logs** on the node.
5. **Node logs** — kubelet, containerd, control-plane components, etcd, host OS.
6. **API-server audit logs** — durable on disk, subject to rotation policy.
7. **Cluster object specs** — durable in etcd until someone changes them.

---

## 8. Acceptance Criteria

- [ ] Runs against a kubeadm cluster on **containerd** with **zero** `docker` code paths.
- [ ] API-plane collection completes with the shipped **read-only** ClusterRole — no cluster-admin.
- [ ] Missing audit log produces a **critical, prominently-surfaced gap**, not a silent empty result.
- [ ] Events are collected **first**, and the tool warns explicitly when the incident window
      predates the effective `--event-ttl`.
- [ ] A single `ACCESS_DENIED` produces a gap and the run **continues**.
- [ ] Node-plane collector correctly detects containerd vs CRI-O and resolves overlay paths
      dynamically, verified on both.
- [ ] Every artifact has a sha256 in a signed manifest with full provenance.
- [ ] `k8s_checkpoint` probes for capability and degrades to `NOT_SUPPORTED` (no run failure) on
      an unsupported runtime or a GPU-backed container.
- [ ] End-to-end: on a lab cluster where an attacker execs into a pod, reads a secret, creates a
      ClusterRoleBinding, and drops a miner — the tool reconstructs that full sequence from the
      audit log, correlates it with the container filesystem artifact and its hash, and produces
      a single unified timeline.
