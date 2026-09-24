"""API-plane permission pre-flight via ``SelfSubjectAccessReview``.

The build spec requires the tool to verify its own permissions *before* collecting, so the
operator learns what this kubeconfig cannot reach while there is still time to fix the
binding — rather than discovering it as a gap after a long run.

This is a **probe**, never a gate: a denied verb is reported and collection proceeds anyway
(the collector will record its own ``ACCESS_DENIED`` gap). ``SelfSubjectAccessReview`` is the
one write-shaped call the collector makes and it changes no cluster state, which is why it is
allow-listed in the read-only ClusterRole.
"""

from __future__ import annotations

from typing import Any

# resource -> API group. Anything unlisted is core/v1 ("").
_RESOURCE_GROUPS: dict[str, str] = {
    "deployments": "apps",
    "daemonsets": "apps",
    "statefulsets": "apps",
    "replicasets": "apps",
    "jobs": "batch",
    "cronjobs": "batch",
    "networkpolicies": "networking.k8s.io",
    "ingresses": "networking.k8s.io",
    "roles": "rbac.authorization.k8s.io",
    "clusterroles": "rbac.authorization.k8s.io",
    "rolebindings": "rbac.authorization.k8s.io",
    "clusterrolebindings": "rbac.authorization.k8s.io",
    "customresourcedefinitions": "apiextensions.k8s.io",
    "mutatingwebhookconfigurations": "admissionregistration.k8s.io",
    "validatingwebhookconfigurations": "admissionregistration.k8s.io",
    "podsecuritypolicies": "policy",
}


def parse_action(action: str) -> dict[str, str] | None:
    """Turn a declared action string into SelfSubjectAccessReview attributes.

    Handles the three shapes the Kubernetes collectors declare:
      ``"list pods"``            -> verb=list, resource=pods
      ``"get pods/log"``         -> verb=get, resource=pods, subresource=log
      ``"list events.k8s.io events"`` -> verb=list, resource=events, group=events.k8s.io
      ``"get /version"``         -> a non-resource URL probe
    """
    action = action.strip()
    if not action or " " not in action:
        return None
    verb, _, rest = action.partition(" ")
    rest = rest.strip()
    if rest.startswith("/"):
        return {"kind": "url", "verb": verb, "path": rest}

    group = ""
    parts = rest.split()
    if len(parts) == 2:
        # "<group> <resource>" — an explicitly qualified resource (events.k8s.io events).
        group, rest = parts[0], parts[1]

    resource, _, subresource = rest.partition("/")
    if not group:
        group = _RESOURCE_GROUPS.get(resource, "")
    return {
        "kind": "resource",
        "verb": verb,
        "resource": resource,
        "subresource": subresource,
        "group": group,
    }


def probe_permissions(cf: Any, collectors: dict[str, tuple[str, ...]]) -> dict[str, Any]:
    """Probe every declared action for the selected API-plane collectors.

    ``collectors`` maps collector name -> its ``required_actions``. Returns a report with
    per-collector allow/deny, suitable for writing into the evidence package. The probe
    itself failing (no API plane, SSAR denied) is recorded rather than raised.
    """
    report: dict[str, Any] = {
        "available": False,
        "checked": 0,
        "denied": [],
        "collectors": {},
        "note": "",
    }
    if not hasattr(cf, "can_i"):
        report["note"] = "client factory does not support SelfSubjectAccessReview probing."
        return report

    cache: dict[tuple[str, ...], bool | None] = {}
    for name, actions in collectors.items():
        entry: dict[str, Any] = {"allowed": [], "denied": [], "unknown": []}
        for action in actions:
            attrs = parse_action(action)
            if attrs is None:
                continue
            key = tuple(sorted(attrs.items()))
            if key in cache:
                allowed = cache[key]
            else:
                allowed = _check(cf, attrs, report)
                cache[key] = allowed
            report["checked"] += 1
            if allowed is True:
                entry["allowed"].append(action)
            elif allowed is False:
                entry["denied"].append(action)
                if action not in report["denied"]:
                    report["denied"].append(action)
            else:
                entry["unknown"].append(action)
        report["collectors"][name] = entry

    if report["available"]:
        report["note"] = (
            f"{report['checked']} permission(s) probed; {len(report['denied'])} denied. "
            "Denied verbs are collected anyway and recorded as ACCESS_DENIED gaps."
        )
    elif not report["note"]:
        report["note"] = (
            "SelfSubjectAccessReview was not usable (no API plane, or 'create "
            "selfsubjectaccessreviews' is not granted); permissions were not pre-verified."
        )
    return report


def _check(cf: Any, attrs: dict[str, str], report: dict[str, Any]) -> bool | None:
    """One probe. ``None`` means the probe itself could not be performed."""
    try:
        if attrs["kind"] == "url":
            fn = getattr(cf, "can_i_url", None)
            if fn is None:
                return None
            allowed = fn(attrs["verb"], attrs["path"])
        else:
            allowed = cf.can_i(
                attrs["verb"],
                attrs["resource"],
                group=attrs["group"],
                subresource=attrs["subresource"],
            )
    except Exception:  # noqa: BLE001 - a probe must never break the run
        return None
    report["available"] = True
    return bool(allowed)
