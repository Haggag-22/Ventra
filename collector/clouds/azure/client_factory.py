"""Azure / Microsoft Graph client management used by every Azure collector.

Wraps azure-identity + the ARM management SDKs + a thin Microsoft Graph REST client so
collectors never import an Azure SDK directly (which keeps them unit-testable with a fake
factory, exactly like the AWS ``AwsClientFactory`` pattern).

Two collection paths, one factory:
  * **Graph** — Entra sign-in/audit, OAuth grants, directory objects (``graph_paginate``).
  * **ARM management** — Activity Log, Defender, Resource Graph, RBAC, flow-log config.

Auth is an app-registration service principal read from the environment. Both client-secret
and **certificate** credentials are supported, because many client tenants forbid long-lived
secrets. The operator creates the app registration and grants consent; Ventra only consumes
the credential. Access/enablement errors are translated into typed gaps — evidence, not crashes.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"

from collector.lib.limits import UNLIMITED_RECORDS

# Default pagination ceiling for API-backed pulls (full since/until window unless acquisition.yaml
# sets max_records_per_source to a positive triage cap).
MAX_RECORDS = UNLIMITED_RECORDS
# Graph throttles aggressively; cap retry waits so a run can't hang indefinitely.
MAX_RETRIES = 5


def _subscription_client(credential: Any) -> Any:
    """Compatible with azure-mgmt-resource 24.x (top-level) and 25+ (subscriptions package)."""
    try:
        from azure.mgmt.resource.subscriptions import SubscriptionClient
    except ImportError:
        from azure.mgmt.resource import SubscriptionClient
    return SubscriptionClient(credential)


def _resource_management_client(credential: Any, subscription_id: str) -> Any:
    try:
        from azure.mgmt.resource.resources import ResourceManagementClient
    except ImportError:
        from azure.mgmt.resource import ResourceManagementClient
    return ResourceManagementClient(credential, subscription_id)


class AzureAccessDenied(Exception):
    """Raised when an API returns an authorization/consent failure (a recorded gap)."""

    def __init__(self, action: str, message: str) -> None:
        super().__init__(f"{action}: {message}")
        self.action = action
        self.message = message


class AzureServiceNotEnabled(Exception):
    """Raised when a service/feature/license isn't present (e.g. sign-in logs need Entra P1)."""

    def __init__(self, service: str, message: str) -> None:
        super().__init__(f"{service}: {message}")
        self.service = service
        self.message = message


@dataclass
class AzureIdentity:
    tenant_id: str
    principal: str  # the app registration's client id (chain-of-custody operator)
    tenant_name: str = ""
    subscription_ids: list[str] = field(default_factory=list)


class AzureClientFactory:
    """Creates credentials, Graph requests, and ARM SDK clients from one service principal."""

    def __init__(
        self,
        credential: Any = None,
        *,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        client_certificate_path: str | None = None,
        client_certificate_password: str | None = None,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._tenant_id_override = tenant_id
        self._client_id_override = client_id
        self._client_secret_override = client_secret
        self._cert_path_override = client_certificate_path
        self._cert_password_override = client_certificate_password
        self._tokens: dict[str, tuple[str, float]] = {}
        self._session = requests.Session()

    # -- credential -----------------------------------------------------------------------

    def credential(self) -> Any:
        """Build a service-principal credential from the environment (secret or certificate).

        Honors the standard ``AZURE_*`` env vars. A certificate (``AZURE_CLIENT_CERTIFICATE_PATH``)
        is preferred when present, since secret-less auth is increasingly mandated; otherwise a
        client secret is used. Falls back to ``DefaultAzureCredential`` (az login / managed
        identity) when no explicit SP env vars are set.
        """
        if self._credential is not None:
            return self._credential
        tenant = self._tenant_id_override or os.environ.get("AZURE_TENANT_ID")
        client = self._client_id_override or os.environ.get("AZURE_CLIENT_ID")
        cert_path = self._cert_path_override or os.environ.get("AZURE_CLIENT_CERTIFICATE_PATH")
        secret = self._client_secret_override or os.environ.get("AZURE_CLIENT_SECRET")
        cert_password = (
            self._cert_password_override or os.environ.get("AZURE_CLIENT_CERTIFICATE_PASSWORD") or None
        )
        try:
            if tenant and client and cert_path:
                from azure.identity import CertificateCredential

                self._credential = CertificateCredential(
                    tenant_id=tenant,
                    client_id=client,
                    certificate_path=cert_path,
                    password=cert_password,
                )
            elif tenant and client and secret:
                from azure.identity import ClientSecretCredential

                self._credential = ClientSecretCredential(
                    tenant_id=tenant, client_id=client, client_secret=secret
                )
            else:
                from azure.identity import DefaultAzureCredential

                self._credential = DefaultAzureCredential()
        except Exception as exc:  # pragma: no cover - credential construction failure
            raise RuntimeError(
                "No Azure credentials found. Set AZURE_TENANT_ID / AZURE_CLIENT_ID and either "
                "AZURE_CLIENT_SECRET or AZURE_CLIENT_CERTIFICATE_PATH, or run `az login`."
            ) from exc
        return self._credential

    def _token(self, scope: str) -> str:
        tok = self._tokens.get(scope)
        now = time.time()
        if tok and tok[1] - 60 > now:
            return tok[0]
        access = self.credential().get_token(scope)
        self._tokens[scope] = (access.token, access.expires_on)
        return access.token

    # -- identity / scope -----------------------------------------------------------------

    def caller_identity(self) -> AzureIdentity:
        tenant_id = self._tenant_id_override or os.environ.get("AZURE_TENANT_ID", "")
        client_id = self._client_id_override or os.environ.get("AZURE_CLIENT_ID", "")
        tenant_name = ""
        try:
            org = self.graph_get("organization")
            items = org.get("value") or []
            if items:
                tenant_id = items[0].get("id") or tenant_id
                tenant_name = items[0].get("displayName", "")
        except (AzureAccessDenied, AzureServiceNotEnabled):
            pass  # Directory.Read.All may be absent; tenant id from env is enough for the manifest
        return AzureIdentity(
            tenant_id=tenant_id,
            principal=client_id or "service-principal",
            tenant_name=tenant_name,
        )

    def subscriptions(self) -> list[str]:
        if self._subscription_id:
            return [s.strip() for s in self._subscription_id.split(",") if s.strip()]
        try:
            client = _subscription_client(self.credential())
            return [s.subscription_id for s in client.subscriptions.list() if s.subscription_id]
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, "subscriptions:list")
            return []

    # -- Microsoft Graph ------------------------------------------------------------------

    def graph_get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{GRAPH_BASE}/{path.lstrip('/')}"
        return self._graph_request(url, params)

    def graph_paginate(
        self, path: str, *, params: dict[str, Any] | None = None, max_records: int = MAX_RECORDS
    ) -> Iterator[dict[str, Any]]:
        """Yield items across Graph pages, following ``@odata.nextLink`` with 429 backoff."""
        url: str | None = path if path.startswith("http") else f"{GRAPH_BASE}/{path.lstrip('/')}"
        first = True
        emitted = 0
        while url and emitted < max_records:
            page = self._graph_request(url, params if first else None)
            first = False
            for item in page.get("value") or []:
                if emitted >= max_records:
                    return
                yield item
                emitted += 1
            url = page.get("@odata.nextLink")

    def _graph_request(self, url: str, params: dict[str, Any] | None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token(GRAPH_SCOPE)}", "Accept": "application/json"}
        for attempt in range(MAX_RETRIES + 1):
            resp = self._session.get(url, headers=headers, params=params, timeout=60)
            if resp.status_code == 429 and attempt < MAX_RETRIES:
                time.sleep(min(int(resp.headers.get("Retry-After", "2")), 30))
                continue
            if resp.status_code in (401, 403):
                raise AzureAccessDenied(f"graph:{url}", _graph_error(resp))
            if resp.status_code == 404:
                raise AzureServiceNotEnabled(f"graph:{url}", _graph_error(resp))
            if resp.status_code >= 400:
                # 400 on premium-only endpoints (e.g. sign-in logs without Entra P1).
                raise AzureServiceNotEnabled(f"graph:{url}", _graph_error(resp))
            return resp.json()
        raise AzureServiceNotEnabled(f"graph:{url}", "throttled past retry budget")

    # -- ARM management -------------------------------------------------------------------

    def activity_log_events(
        self, subscription_id: str, filter_str: str, *, max_records: int = MAX_RECORDS
    ) -> Iterator[dict[str, Any]]:
        """Yield Azure Activity Log events for a subscription as plain dicts (``as_dict``)."""
        try:
            from azure.mgmt.monitor import MonitorManagementClient

            client = MonitorManagementClient(self.credential(), subscription_id)
            for i, ev in enumerate(client.activity_logs.list(filter=filter_str)):
                if i >= max_records:
                    return
                yield ev.as_dict() if hasattr(ev, "as_dict") else dict(ev)
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, f"monitor:activity_logs:{subscription_id}")

    # -- network flow logs (discovery + blob access) --------------------------------------

    def network_flow_logs(self, subscription_id: str) -> list[dict[str, Any]]:
        """Discover configured flow logs in a subscription (VNet + NSG).

        Returns ``[{name, target_resource_id, storage_id, enabled, flow_type}]``. ``flow_type``
        is ``"vnet"`` or ``"nsg"`` inferred from the target resource. A resource with no flow
        log simply doesn't appear here — the collector turns that absence into a coverage gap.
        """
        out: list[dict[str, Any]] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self.credential(), subscription_id)
            for watcher in client.network_watchers.list_all():
                wid = watcher.id or ""
                rg = _segment(wid, "resourceGroups")
                name = wid.rsplit("/", 1)[-1]
                if not rg or not name:
                    continue
                for fl in client.flow_logs.list(rg, name):
                    target = (fl.target_resource_id or "").lower()
                    flow_type = "nsg" if "/networksecuritygroups/" in target else "vnet"
                    out.append(
                        {
                            "name": fl.name,
                            "target_resource_id": fl.target_resource_id or "",
                            "storage_id": fl.storage_id or "",
                            "enabled": bool(fl.enabled),
                            "flow_type": flow_type,
                        }
                    )
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, f"network:flow_logs:{subscription_id}")
        return out

    def container_client(self, storage_id: str, container: str) -> Any:
        """A blob ContainerClient for a storage account resource id (needs Storage Blob Data Reader)."""
        from azure.storage.blob import BlobServiceClient

        account = storage_id.rsplit("/", 1)[-1]
        url = f"https://{account}.blob.core.windows.net"
        return BlobServiceClient(url, credential=self.credential()).get_container_client(container)

    # -- generic resource + diagnostic-settings discovery (Tier C/D/E + gap analysis) ------

    def resources_of_type(self, subscription_id: str, resource_types: list[str]) -> list[dict[str, Any]]:
        """List resources of the given ARM types in a subscription (no per-service SDK needed)."""
        out: list[dict[str, Any]] = []
        try:
            client = _resource_management_client(self.credential(), subscription_id)
            for rt in resource_types:
                for r in client.resources.list(filter=f"resourceType eq '{rt}'"):
                    out.append(
                        {
                            "id": r.id or "",
                            "name": r.name or "",
                            "type": r.type or "",
                            "location": r.location or "",
                        }
                    )
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, f"resources:{subscription_id}")
        return out

    def _arm_request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Authenticated ARM REST call with 429 backoff."""
        headers = {
            "Authorization": f"Bearer {self._token(ARM_SCOPE)}",
            "Accept": "application/json",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(MAX_RETRIES + 1):
            resp = self._session.request(
                method, url, headers=headers, params=params, json=json_body, timeout=60
            )
            if resp.status_code == 429 and attempt < MAX_RETRIES:
                time.sleep(min(int(resp.headers.get("Retry-After", "2")), 30))
                continue
            if resp.status_code in (401, 403):
                raise AzureAccessDenied(f"arm:{url}", _graph_error(resp))
            if resp.status_code in (400, 404):
                raise AzureServiceNotEnabled(f"arm:{url}", _graph_error(resp))
            if resp.status_code >= 400:
                raise AzureServiceNotEnabled(f"arm:{url}", _graph_error(resp))
            if resp.status_code == 204 or not resp.content:
                return {}
            return resp.json()
        raise AzureServiceNotEnabled(f"arm:{url}", "throttled past retry budget")

    def _arm_paginate(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        value_key: str = "value",
        max_records: int = MAX_RECORDS,
    ) -> Iterator[dict[str, Any]]:
        """Follow ``nextLink`` on ARM list endpoints."""
        emitted = 0
        next_url: str | None = url
        next_params = params
        while next_url and emitted < max_records:
            page = self._arm_request("GET", next_url, params=next_params)
            next_params = None
            for item in page.get(value_key) or []:
                if emitted >= max_records:
                    return
                yield item
                emitted += 1
            next_url = page.get("nextLink")

    def security_alerts(
        self, subscription_id: str, *, max_records: int = MAX_RECORDS
    ) -> Iterator[dict[str, Any]]:
        """Yield Microsoft Defender for Cloud alerts for a subscription."""
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            "/providers/Microsoft.Security/alerts"
        )
        try:
            yield from self._arm_paginate(url, params={"api-version": "2022-01-01"}, max_records=max_records)
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, f"security:alerts:{subscription_id}")

    def resource_graph_query(
        self,
        query: str,
        subscriptions: list[str],
        *,
        max_records: int = MAX_RECORDS,
    ) -> list[dict[str, Any]]:
        """Run a Resource Graph KQL query across in-scope subscriptions."""
        url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
        body = {"query": query, "subscriptions": subscriptions, "options": {"$top": max_records}}
        try:
            result = self._arm_request("POST", url, params={"api-version": "2021-03-01"}, json_body=body)
            return list(result.get("data") or [])[:max_records]
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, "resourcegraph:query")
            return []

    def managed_clusters(self, subscription_id: str) -> list[dict[str, Any]]:
        """List AKS managed clusters in a subscription."""
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            "/providers/Microsoft.ContainerService/managedClusters"
        )
        try:
            return list(self._arm_paginate(url, params={"api-version": "2024-02-01"}))
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, f"aks:list:{subscription_id}")
            return []

    def rbac_snapshot(self, subscription_id: str) -> dict[str, Any]:
        """Role definitions + assignments at subscription scope."""
        scope = f"/subscriptions/{subscription_id}"
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient

            client = AuthorizationManagementClient(self.credential(), subscription_id)
            role_definitions = [
                rd.as_dict() if hasattr(rd, "as_dict") else dict(rd)
                for rd in client.role_definitions.list(scope=scope)
            ]
            role_assignments = [
                ra.as_dict() if hasattr(ra, "as_dict") else dict(ra)
                for ra in client.role_assignments.list_for_subscription()
            ]
            return {"role_definitions": role_definitions, "role_assignments": role_assignments}
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, f"rbac:{subscription_id}")
            return {"role_definitions": [], "role_assignments": []}

    def subscription_details(self) -> list[dict[str, Any]]:
        """In-scope subscription metadata (id, name, tenant, state)."""
        try:
            client = _subscription_client(self.credential())
            out: list[dict[str, Any]] = []
            for sub in client.subscriptions.list():
                out.append(
                    {
                        "subscription_id": sub.subscription_id or "",
                        "display_name": sub.display_name or "",
                        "tenant_id": sub.tenant_id or "",
                        "state": str(sub.state or ""),
                    }
                )
            return out
        except Exception as exc:  # noqa: BLE001
            _raise_typed_azure(exc, "subscriptions:details")
            return []

    def diagnostic_settings(self, resource_id: str) -> list[dict[str, Any]]:
        """Where a resource routes its logs + which log categories are enabled.

        Powers both collection (read from the Storage destination) and gap analysis (no setting,
        or routed only to Log Analytics / Event Hub, = a logging blind spot to report).

        Uses ARM REST. azure-mgmt-monitor 7.0.0 dropped ``diagnostic_settings`` from
        ``MonitorManagementClient``, so the SDK call crashes before any permission check.
        """
        url = f"https://management.azure.com{resource_id}/providers/Microsoft.Insights/diagnosticSettings"
        page = self._arm_request("GET", url, params={"api-version": "2021-05-01-preview"})
        out: list[dict[str, Any]] = []
        for setting in page.get("value") or []:
            props = setting.get("properties") or {}
            categories: list[str] = []
            groups: list[str] = []
            for log in props.get("logs") or []:
                if not log.get("enabled", False):
                    continue
                if log.get("category"):
                    categories.append(log["category"])
                if log.get("categoryGroup"):
                    groups.append(log["categoryGroup"])
            if any(group.lower() == "alllogs" for group in groups):
                discovered = self._diagnostic_log_category_names(resource_id)
                if discovered:
                    categories = discovered
            out.append(
                {
                    "storage_account_id": props.get("storageAccountId") or "",
                    "workspace_id": props.get("workspaceId") or "",
                    "event_hub": props.get("eventHubAuthorizationRuleId") or "",
                    "categories": categories,
                    "category_groups": groups,
                }
            )
        return out

    def _diagnostic_log_category_names(self, resource_id: str) -> list[str]:
        """Log category names for a resource. Used when a setting enables the allLogs group."""
        url = (
            "https://management.azure.com"
            f"{resource_id}/providers/Microsoft.Insights/diagnosticSettingsCategories"
        )
        try:
            page = self._arm_request("GET", url, params={"api-version": "2021-05-01-preview"})
        except AzureServiceNotEnabled:
            return []
        names: list[str] = []
        for item in page.get("value") or []:
            props = item.get("properties") or {}
            if str(props.get("categoryType") or "").lower() != "logs":
                continue
            name = item.get("name") or props.get("name") or ""
            if name:
                names.append(name)
        return names


def _segment(resource_id: str, key: str) -> str:
    """Extract ``<value>`` from an ARM id segment ``.../<key>/<value>/...`` (case-insensitive)."""
    parts = resource_id.split("/")
    low = [p.lower() for p in parts]
    try:
        return parts[low.index(key.lower()) + 1]
    except (ValueError, IndexError):
        return ""


def _session_id_from_rows(rows: list[dict[str, Any]]) -> str | None:
    for row in rows:
        sid = row.get("SessionId") or row.get("sessionId")
        if sid:
            return str(sid)
    return None


def _graph_error(resp: requests.Response) -> str:
    try:
        body = resp.json()
        return str((body.get("error") or {}).get("message") or resp.text[:200])
    except ValueError:
        return resp.text[:200]


def _raise_typed_azure(exc: Exception, action: str) -> None:
    """Translate an azure-core exception into a typed gap, or re-raise if unexpected."""
    status = getattr(exc, "status_code", None)
    msg = getattr(exc, "message", None) or str(exc)
    # azure.core ClientAuthenticationError / HttpResponseError carry status_code.
    if status in (401, 403) or "AuthorizationFailed" in msg or "Forbidden" in msg:
        raise AzureAccessDenied(action, msg) from exc
    if status in (400, 404) or "SubscriptionNotFound" in msg or "NotFound" in msg:
        raise AzureServiceNotEnabled(action, msg) from exc
    raise exc
