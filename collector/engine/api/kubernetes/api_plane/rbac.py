"""k8s_rbac — RBAC snapshot with effective-permission analysis.

Privilege escalation via RBAC is the most common post-exploitation move, and the binding
object itself is durable evidence. This collects Roles, ClusterRoles, RoleBindings,
ClusterRoleBindings and ServiceAccounts, then flags subjects that can pivot to cluster-admin
(exec into pods, read secrets cluster-wide, escalate/bind roles, impersonate) and any binding
to an anonymous/unauthenticated subject.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeNotFound
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus

from ..common.analysis import ANONYMOUS_SUBJECTS, rbac_escalation_findings


class RbacCollector(Collector):
    name = "k8s_rbac"
    priority = 1
    plane = "api"
    description = "RBAC roles/bindings snapshot with escalation-path analysis."
    required_actions = (
        "list roles", "list clusterroles",
        "list rolebindings", "list clusterrolebindings",
        "list serviceaccounts",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        files = []

        roles = self._safe("roles", cf.list_roles, gaps) or []
        cluster_roles = self._safe("clusterroles", cf.list_cluster_roles, gaps) or []
        role_bindings = self._safe("rolebindings", cf.list_role_bindings, gaps) or []
        crbs = self._safe("clusterrolebindings", cf.list_cluster_role_bindings, gaps) or []
        service_accounts = self._safe("serviceaccounts", cf.list_service_accounts, gaps) or []

        # Map role name -> escalation reasons for cluster roles and roles.
        role_powers = self._role_powers(cluster_roles, roles)
        dangerous = self._dangerous_bindings(crbs, role_bindings, role_powers)
        anon = self._anonymous_bindings(crbs, role_bindings)
        _stamp_verdicts(roles, cluster_roles, role_bindings, crbs, role_powers)

        if dangerous:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    f"{len(dangerous)} binding(s) grant escalation-capable permissions "
                    "(exec/secrets/escalate/bind/impersonate/cluster-admin).",
                )
            )
        if anon:
            gaps.append(
                (
                    self.name,
                    GapReason.NOT_PRESENT,
                    f"{len(anon)} binding(s) target system:anonymous / system:unauthenticated.",
                )
            )

        for kind, rows in (
            ("roles", roles),
            ("clusterroles", cluster_roles),
            ("rolebindings", role_bindings),
            ("clusterrolebindings", crbs),
            ("serviceaccounts", service_accounts),
        ):
            if rows:
                files.append(self.write_jsonl(rows, f"{kind}.jsonl.gz"))

        files.append(self.write_json(dangerous, "dangerous_bindings.json"))
        files.append(self.write_json(anon, "anonymous_bindings.json"))
        config = {
            "counts": {
                "roles": len(roles),
                "clusterroles": len(cluster_roles),
                "rolebindings": len(role_bindings),
                "clusterrolebindings": len(crbs),
                "serviceaccounts": len(service_accounts),
            },
            "dangerous_binding_count": len(dangerous),
            "anonymous_binding_count": len(anon),
        }
        files.append(self.write_json(config, "config.json"))
        self.write_meta({"source": self.name, **config})

        total = len(roles) + len(cluster_roles) + len(role_bindings) + len(crbs)
        status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        if total == 0 and not gaps:
            status = SourceStatus.EMPTY
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=total,
            gaps=gaps,
            notes=f"{total} RBAC object(s); {len(dangerous)} escalation-capable, "
            f"{len(anon)} anonymous binding(s).",
        )

    def _safe(
        self,
        kind: str,
        fn: Callable[[], list[dict[str, Any]]],
        gaps: list[tuple[str, GapReason, str]],
    ) -> list[dict[str, Any]] | None:
        try:
            rows = fn()
        except KubeAccessDenied as exc:
            gaps.append((self.name, GapReason.ACCESS_DENIED, f"{kind}: {exc.message}"))
            return None
        except KubeNotFound as exc:
            gaps.append((self.name, GapReason.NOT_PRESENT, f"{kind}: {exc.message}"))
            return None
        except Exception as exc:  # noqa: BLE001
            gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"{kind}: {exc}"))
            return None
        for row in rows:
            row["_ventra_cluster"] = self.ctx.account_id
            # List items come back without ``kind``; stamp it so the ingester can normalize
            # roles, bindings and service accounts out of one mixed source.
            row["_ventra_kind"] = kind
        return rows

    @staticmethod
    def _role_powers(
        cluster_roles: list[dict[str, Any]], roles: list[dict[str, Any]]
    ) -> dict[str, list[str]]:
        powers: dict[str, list[str]] = {}
        for role in cluster_roles:
            name = (role.get("metadata") or {}).get("name", "")
            findings = rbac_escalation_findings(role.get("rules") or [])
            if name == "cluster-admin":
                findings = ["cluster-admin"] + findings
            if findings:
                powers[f"ClusterRole/{name}"] = findings
        for role in roles:
            meta = role.get("metadata") or {}
            name = meta.get("name", "")
            ns = meta.get("namespace", "")
            findings = rbac_escalation_findings(role.get("rules") or [])
            if findings:
                powers[f"Role/{ns}/{name}"] = findings
        return powers

    def _dangerous_bindings(
        self,
        crbs: list[dict[str, Any]],
        role_bindings: list[dict[str, Any]],
        role_powers: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for binding in crbs:
            out.extend(self._match_binding(binding, role_powers, cluster_scoped=True))
        for binding in role_bindings:
            out.extend(self._match_binding(binding, role_powers, cluster_scoped=False))
        return out

    @staticmethod
    def _match_binding(
        binding: dict[str, Any],
        role_powers: dict[str, list[str]],
        *,
        cluster_scoped: bool,
    ) -> list[dict[str, Any]]:
        ref = binding.get("role_ref") or binding.get("roleRef") or {}
        kind = ref.get("kind", "")
        name = ref.get("name", "")
        meta = binding.get("metadata") or {}
        ns = meta.get("namespace", "")
        keys = [f"ClusterRole/{name}"]
        if kind == "Role":
            keys.append(f"Role/{ns}/{name}")
        findings: list[str] = []
        for key in keys:
            findings.extend(role_powers.get(key, []))
        if not findings:
            return []
        subjects = binding.get("subjects") or []
        return [
            {
                "binding": f"{'ClusterRoleBinding' if cluster_scoped else 'RoleBinding'}/"
                f"{meta.get('name', '')}",
                "role": f"{kind}/{name}",
                "grants": sorted(set(findings)),
                "subjects": [_subject_str(s) for s in subjects],
            }
        ]

    @staticmethod
    def _anonymous_bindings(
        crbs: list[dict[str, Any]], role_bindings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for binding in crbs + role_bindings:
            meta = binding.get("metadata") or {}
            for subject in binding.get("subjects") or []:
                if str(subject.get("name", "")) in ANONYMOUS_SUBJECTS:
                    ref = binding.get("role_ref") or binding.get("roleRef") or {}
                    out.append(
                        {
                            "binding": meta.get("name", ""),
                            "subject": _subject_str(subject),
                            "role": f"{ref.get('kind', '')}/{ref.get('name', '')}",
                        }
                    )
        return out


def _stamp_verdicts(
    roles: list[dict[str, Any]],
    cluster_roles: list[dict[str, Any]],
    role_bindings: list[dict[str, Any]],
    crbs: list[dict[str, Any]],
    role_powers: dict[str, list[str]],
) -> None:
    """Write each object's own verdict onto it before the evidence is sealed.

    A binding read on its own says nothing — the danger lives in the role it references. By
    stamping the resolved grants (and the anonymous-subject flag) onto the record, both the
    analyst reading rolebindings.jsonl.gz and the ingester normalizing it can see *why* a
    binding matters without recomputing the cross-reference.
    """
    for role in cluster_roles:
        name = (role.get("metadata") or {}).get("name", "")
        grants = list(role_powers.get(f"ClusterRole/{name}", []))
        if grants:
            role["_ventra_grants"] = grants
    for role in roles:
        meta = role.get("metadata") or {}
        grants = list(
            role_powers.get(f"Role/{meta.get('namespace', '')}/{meta.get('name', '')}", [])
        )
        if grants:
            role["_ventra_grants"] = grants

    for binding in list(crbs) + list(role_bindings):
        ref = binding.get("role_ref") or binding.get("roleRef") or {}
        kind = ref.get("kind", "")
        name = ref.get("name", "")
        ns = (binding.get("metadata") or {}).get("namespace", "")
        grants: list[str] = list(role_powers.get(f"ClusterRole/{name}", []))
        if kind == "Role":
            grants.extend(role_powers.get(f"Role/{ns}/{name}", []))
        if grants:
            binding["_ventra_grants"] = sorted(set(grants))
        subjects = [
            str(s.get("name", "")) for s in (binding.get("subjects") or []) if isinstance(s, dict)
        ]
        anonymous = sorted({s for s in subjects if s in ANONYMOUS_SUBJECTS})
        if anonymous:
            binding["_ventra_anonymous_subjects"] = anonymous


def _subject_str(subject: dict[str, Any]) -> str:
    kind = subject.get("kind", "")
    ns = subject.get("namespace", "")
    name = subject.get("name", "")
    return "/".join(p for p in (kind, ns, name) if p)
