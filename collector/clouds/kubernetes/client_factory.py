"""Kubernetes API-plane client factory for on-prem clusters.

This wraps the official ``kubernetes`` Python client the way :class:`AwsClientFactory` wraps
boto3: collectors never touch credentials or SDK objects directly, they call typed helpers
that return plain ``dict`` records and translate a ``403`` into :class:`KubeAccessDenied`
(a *gap*, recorded as evidence — never a crash).

The real ``kubernetes`` client is imported lazily so that:
  * AWS/Azure/GCP kits never import it, and
  * tests can inject a fake factory exposing the same high-level methods without the wheel.

Every helper is a **read-only** verb (``get`` / ``list`` / ``watch``). The one write-shaped
call is ``SelfSubjectAccessReview`` (``create`` on ``selfsubjectaccessreviews``), which is a
permission *probe* that changes no cluster state — this is why it is allow-listed in the
read-only ClusterRole and in the collector guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .node import NodeAccess


class KubeAccessDenied(Exception):
    """The API server returned 401/403 — the caller records ACCESS_DENIED and continues."""

    def __init__(self, action: str, message: str) -> None:
        super().__init__(f"{action}: {message}")
        self.action = action
        self.message = message


class KubeNotFound(Exception):
    """A resource type or object does not exist (404) — treated as NOT_PRESENT."""

    def __init__(self, action: str, message: str) -> None:
        super().__init__(f"{action}: {message}")
        self.action = action
        self.message = message


class KubeUnreachable(Exception):
    """The API server could not be reached (DNS/transport) — not a permissions problem."""


@dataclass
class KubeIdentity:
    """Who/what we authenticated as, plus the cluster we are pointed at."""

    cluster_id: str  # host or context name — the manifest ``account_id`` for this platform
    server_url: str
    server_version: str
    username: str = ""
    context: str = ""


class KubernetesClientFactory:
    """Creates and caches Kubernetes API clients from a kubeconfig.

    ``node`` is the node-plane accessor; API-plane collectors ignore it and node-plane
    collectors use it exclusively (they never call the API helpers here).
    """

    def __init__(
        self,
        *,
        kubeconfig_content: str = "",
        kubeconfig_path: str = "",
        context: str = "",
        node: NodeAccess | None = None,
    ) -> None:
        self._kubeconfig_content = kubeconfig_content
        self._kubeconfig_path = kubeconfig_path
        self._context = context
        self.node = node or NodeAccess()
        self._api_client: Any = None
        self._clients: dict[str, Any] = {}

    # -- lazy client construction ---------------------------------------------------------

    def _load(self) -> Any:
        if self._api_client is not None:
            return self._api_client
        try:
            from kubernetes import client, config  # noqa: PLC0415
            from kubernetes.config.config_exception import ConfigException  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "The 'kubernetes' package is required for Kubernetes API-plane collection. "
                "Install it with: uv pip install kubernetes"
            ) from exc

        try:
            if self._kubeconfig_content:
                import yaml  # noqa: PLC0415

                loader = config.kube_config.KubeConfigLoader(
                    config_dict=yaml.safe_load(self._kubeconfig_content),
                    active_context=self._context or None,
                )
                cfg = client.Configuration()
                loader.load_and_set(cfg)
                self._api_client = client.ApiClient(configuration=cfg)
            elif self._kubeconfig_path:
                self._api_client = config.new_client_from_config(
                    config_file=self._kubeconfig_path, context=self._context or None
                )
            else:
                # In-cluster (node-plane pod) or default kubeconfig on the operator box.
                try:
                    config.load_incluster_config()
                except ConfigException:
                    config.load_kube_config(context=self._context or None)
                self._api_client = client.ApiClient()
        except ConfigException as exc:
            raise KubeUnreachable(f"could not load kubeconfig: {exc}") from exc
        return self._api_client

    def _client(self, name: str) -> Any:
        if name not in self._clients:
            from kubernetes import client  # noqa: PLC0415

            api = self._load()
            factory = getattr(client, name)
            self._clients[name] = factory(api)
        return self._clients[name]

    # -- error translation ----------------------------------------------------------------

    @staticmethod
    def _translate(action: str, exc: Exception) -> Exception:
        try:
            from kubernetes.client.rest import ApiException  # noqa: PLC0415
        except ImportError:  # pragma: no cover
            return exc
        if isinstance(exc, ApiException):
            if exc.status in (401, 403):
                return KubeAccessDenied(action, exc.reason or "forbidden")
            if exc.status == 404:
                return KubeNotFound(action, exc.reason or "not found")
        return exc

    def _list(self, action: str, fn: Any, **kwargs: Any) -> list[dict[str, Any]]:
        """Call a list_* method and return each item as a plain dict."""
        try:
            resp = fn(**kwargs)
        except Exception as exc:  # noqa: BLE001 - re-typed below
            raise self._translate(action, exc) from exc
        items = getattr(resp, "items", None)
        if items is None and isinstance(resp, dict):
            items = resp.get("items", [])
        out: list[dict[str, Any]] = []
        for item in items or []:
            out.append(item.to_dict() if hasattr(item, "to_dict") else dict(item))
        return out

    # -- identity / pre-flight ------------------------------------------------------------

    def cluster_identity(self) -> KubeIdentity:
        api = self._load()
        cfg = getattr(api, "configuration", None)
        server = getattr(cfg, "host", "") if cfg else ""
        version = ""
        try:
            from kubernetes import client  # noqa: PLC0415

            info = client.VersionApi(api).get_code()
            version = getattr(info, "git_version", "") or ""
        except Exception:  # noqa: BLE001 - version is best-effort
            version = ""
        cluster_id = self._context or (server.split("//")[-1] if server else "in-cluster")
        return KubeIdentity(
            cluster_id=cluster_id,
            server_url=server,
            server_version=version,
            context=self._context,
        )

    def can_i(
        self,
        verb: str,
        resource: str,
        *,
        group: str = "",
        subresource: str = "",
        namespace: str = "",
    ) -> bool:
        """SelfSubjectAccessReview: does our token have ``verb`` on ``resource``?"""
        from kubernetes import client  # noqa: PLC0415

        auth = self._client("AuthorizationV1Api")
        attrs = client.V1ResourceAttributes(
            verb=verb,
            resource=resource,
            group=group or "",
            subresource=subresource or None,
            namespace=namespace or None,
        )
        body = client.V1SelfSubjectAccessReview(
            spec=client.V1SelfSubjectAccessReviewSpec(resource_attributes=attrs)
        )
        try:
            review = auth.create_self_subject_access_review(body)
        except Exception as exc:  # noqa: BLE001
            raise self._translate("create selfsubjectaccessreviews", exc) from exc
        return bool(getattr(review.status, "allowed", False))

    # -- core/v1 --------------------------------------------------------------------------

    def list_events(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list events", core.list_event_for_all_namespaces)

    def list_pods(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list pods", core.list_pod_for_all_namespaces)

    def list_namespaces(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list namespaces", core.list_namespace)

    def list_nodes(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list nodes", core.list_node)

    def list_service_accounts(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list serviceaccounts", core.list_service_account_for_all_namespaces)

    def list_config_maps(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list configmaps", core.list_config_map_for_all_namespaces)

    def list_services(self) -> list[dict[str, Any]]:
        core = self._client("CoreV1Api")
        return self._list("list services", core.list_service_for_all_namespaces)

    def list_secrets_metadata(self) -> list[dict[str, Any]]:
        """Secrets with the ``data``/``string_data`` payloads stripped — metadata only."""
        core = self._client("CoreV1Api")
        rows = self._list("list secrets", core.list_secret_for_all_namespaces)
        for row in rows:
            row.pop("data", None)
            row.pop("string_data", None)
            row.pop("stringData", None)
        return rows

    def read_pod_log(
        self, namespace: str, pod: str, container: str, *, previous: bool = False
    ) -> str:
        core = self._client("CoreV1Api")
        try:
            return core.read_namespaced_pod_log(
                name=pod,
                namespace=namespace,
                container=container,
                previous=previous,
                timestamps=True,
                insecure_skip_tls_verify_backend=False,
            )
        except Exception as exc:  # noqa: BLE001
            raise self._translate("get pods/log", exc) from exc

    # -- apps/v1 --------------------------------------------------------------------------

    def list_deployments(self) -> list[dict[str, Any]]:
        apps = self._client("AppsV1Api")
        return self._list("list deployments", apps.list_deployment_for_all_namespaces)

    def list_daemon_sets(self) -> list[dict[str, Any]]:
        apps = self._client("AppsV1Api")
        return self._list("list daemonsets", apps.list_daemon_set_for_all_namespaces)

    def list_stateful_sets(self) -> list[dict[str, Any]]:
        apps = self._client("AppsV1Api")
        return self._list("list statefulsets", apps.list_stateful_set_for_all_namespaces)

    def list_replica_sets(self) -> list[dict[str, Any]]:
        apps = self._client("AppsV1Api")
        return self._list("list replicasets", apps.list_replica_set_for_all_namespaces)

    # -- batch/v1 -------------------------------------------------------------------------

    def list_jobs(self) -> list[dict[str, Any]]:
        batch = self._client("BatchV1Api")
        return self._list("list jobs", batch.list_job_for_all_namespaces)

    def list_cron_jobs(self) -> list[dict[str, Any]]:
        batch = self._client("BatchV1Api")
        return self._list("list cronjobs", batch.list_cron_job_for_all_namespaces)

    # -- networking/v1 --------------------------------------------------------------------

    def list_ingresses(self) -> list[dict[str, Any]]:
        net = self._client("NetworkingV1Api")
        return self._list("list ingresses", net.list_ingress_for_all_namespaces)

    def list_network_policies(self) -> list[dict[str, Any]]:
        net = self._client("NetworkingV1Api")
        return self._list("list networkpolicies", net.list_network_policy_for_all_namespaces)

    # -- rbac/v1 --------------------------------------------------------------------------

    def list_roles(self) -> list[dict[str, Any]]:
        rbac = self._client("RbacAuthorizationV1Api")
        return self._list("list roles", rbac.list_role_for_all_namespaces)

    def list_cluster_roles(self) -> list[dict[str, Any]]:
        rbac = self._client("RbacAuthorizationV1Api")
        return self._list("list clusterroles", rbac.list_cluster_role)

    def list_role_bindings(self) -> list[dict[str, Any]]:
        rbac = self._client("RbacAuthorizationV1Api")
        return self._list("list rolebindings", rbac.list_role_binding_for_all_namespaces)

    def list_cluster_role_bindings(self) -> list[dict[str, Any]]:
        rbac = self._client("RbacAuthorizationV1Api")
        return self._list("list clusterrolebindings", rbac.list_cluster_role_binding)

    # -- apiextensions + admissionregistration --------------------------------------------

    def list_crds(self) -> list[dict[str, Any]]:
        ext = self._client("ApiextensionsV1Api")
        return self._list("list customresourcedefinitions", ext.list_custom_resource_definition)

    def list_mutating_webhooks(self) -> list[dict[str, Any]]:
        adm = self._client("AdmissionregistrationV1Api")
        return self._list(
            "list mutatingwebhookconfigurations", adm.list_mutating_webhook_configuration
        )

    def list_validating_webhooks(self) -> list[dict[str, Any]]:
        adm = self._client("AdmissionregistrationV1Api")
        return self._list(
            "list validatingwebhookconfigurations", adm.list_validating_webhook_configuration
        )
