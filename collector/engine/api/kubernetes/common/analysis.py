"""Derived-signal helpers shared by the API-plane collectors.

These turn raw cluster objects into the specific things an incident responder looks for:
container-escape-shaped pods, RBAC subjects that can pivot to cluster-admin, and audit-policy
weaknesses. Keeping them here means the collectors stay small and the detection rules are
tested once.
"""

from __future__ import annotations

from typing import Any

# hostPath mounts that are effectively node takeover if writable.
DANGEROUS_HOSTPATHS = (
    "/",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/var/lib/kubelet",
    "/etc/kubernetes",
    "/var/lib/containerd",
    "/proc",
)

# Capabilities that grant container escape / host visibility.
DANGEROUS_CAPS = frozenset({"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH"})

# Cluster-scoped power verbs on high-value resources → privilege-escalation candidates.
_ESCALATION_RULES: tuple[tuple[str, str, str], ...] = (
    ("create", "pods/exec", "can exec into pods"),
    ("create", "pods/attach", "can attach to pods"),
    ("*", "secrets", "can read secrets cluster-wide"),
    ("get", "secrets", "can read secrets cluster-wide"),
    ("list", "secrets", "can list secrets cluster-wide"),
    ("escalate", "roles", "can escalate role privileges"),
    ("escalate", "clusterroles", "can escalate clusterrole privileges"),
    ("bind", "roles", "can bind arbitrary roles"),
    ("bind", "clusterroles", "can bind arbitrary clusterroles"),
    ("impersonate", "users", "can impersonate users"),
    ("impersonate", "groups", "can impersonate groups"),
    ("*", "*", "wildcard verb+resource (cluster-admin-equivalent)"),
)

ANONYMOUS_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})


def _get(obj: dict[str, Any], *path: str, default: Any = None) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def suspicious_pod_findings(pod: dict[str, Any], *, trusted_registries: list[str]) -> list[str]:
    """Return the reasons ``pod`` looks like an attacker foothold (empty == clean)."""
    findings: list[str] = []
    spec = _get(pod, "spec", default={}) or {}
    meta = _get(pod, "metadata", default={}) or {}
    name = f"{meta.get('namespace', '')}/{meta.get('name', '')}"

    if spec.get("host_network") or spec.get("hostNetwork"):
        findings.append("hostNetwork")
    if spec.get("host_pid") or spec.get("hostPID"):
        findings.append("hostPID")
    if spec.get("host_ipc") or spec.get("hostIPC"):
        findings.append("hostIPC")

    for vol in spec.get("volumes") or []:
        host_path = _get(vol, "host_path", "path") or _get(vol, "hostPath", "path")
        if not host_path:
            continue
        # Any hostPath is worth noting; a match against DANGEROUS_HOSTPATHS is node takeover.
        dangerous = any(host_path == d or host_path.startswith(d + "/") for d in DANGEROUS_HOSTPATHS)
        findings.append(f"hostPath{'!' if dangerous else ''}:{host_path}")

    containers = list(spec.get("containers") or []) + list(
        spec.get("init_containers") or spec.get("initContainers") or []
    )
    for c in containers:
        sc = _get(c, "security_context", default={}) or _get(c, "securityContext", default={}) or {}
        if sc.get("privileged"):
            findings.append(f"privileged:{c.get('name', '')}")
        if sc.get("allow_privilege_escalation") or sc.get("allowPrivilegeEscalation"):
            findings.append(f"allowPrivilegeEscalation:{c.get('name', '')}")
        caps = _get(sc, "capabilities", "add") or []
        for cap in caps:
            if str(cap).upper() in DANGEROUS_CAPS:
                findings.append(f"cap:{cap}")
        image = str(c.get("image", ""))
        if image and trusted_registries and not image_trusted(image, trusted_registries):
            findings.append(f"untrusted_image:{image}")

    if findings:
        findings.insert(0, name)
    return findings


def image_trusted(image: str, trusted: list[str]) -> bool:
    """Whether ``image`` comes from one of the engagement's trusted registries."""
    registry = image.split("/", 1)[0] if "/" in image else "docker.io"
    if "." not in registry and ":" not in registry:
        registry = "docker.io"
    return any(t.lower() in image.lower() or registry.lower().endswith(t.lower()) for t in trusted)


def rbac_escalation_findings(
    rules: list[dict[str, Any]],
) -> list[str]:
    """Given a role's ``rules``, return the escalation reasons it grants."""
    findings: list[str] = []
    for rule in rules or []:
        verbs = [str(v).lower() for v in (rule.get("verbs") or [])]
        resources = [str(r).lower() for r in (rule.get("resources") or [])]
        for verb, resource, reason in _ESCALATION_RULES:
            verb_hit = verb == "*" or verb in verbs or "*" in verbs
            res_hit = resource == "*" or resource in resources or "*" in resources
            if verb_hit and res_hit and reason not in findings:
                findings.append(reason)
    return findings


def audit_policy_weaknesses(policy: dict[str, Any]) -> list[str]:
    """Flag an audit policy that exists but is too weak to be useful.

    A policy that only logs ``Metadata`` for sensitive resources, or omits ``secrets`` /
    ``pods/exec`` entirely, is a gap even though a file is present.
    """
    weaknesses: list[str] = []
    rules = policy.get("rules") or []
    if not rules:
        return ["audit policy has no rules"]

    covers_secrets = False
    covers_exec = False
    metadata_only_sensitive = False
    for rule in rules:
        level = str(rule.get("level", "")).lower()
        resources = _flatten_resources(rule.get("resources") or [])
        if "secrets" in resources:
            covers_secrets = True
            if level == "metadata":
                metadata_only_sensitive = True
        if any(r in ("pods/exec", "pods/attach") for r in resources):
            covers_exec = True

    if not covers_secrets:
        weaknesses.append("policy does not log 'secrets' access")
    if not covers_exec:
        weaknesses.append("policy does not log 'pods/exec' / 'pods/attach'")
    if metadata_only_sensitive:
        weaknesses.append("secrets are logged at Metadata level only (payload/verb context lost)")
    return weaknesses


def _flatten_resources(resource_rules: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for group in resource_rules:
        resources = group.get("resources") or []
        for res in resources:
            out.append(str(res).lower())
    return out
