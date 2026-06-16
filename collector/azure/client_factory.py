"""Azure client factory — credentials, subscription context, ARM + Graph access."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterator

from .common.graph import GRAPH_SCOPE, graph_get_pages
from .common.serialize import to_dict


class AccessDenied(Exception):
    def __init__(self, action: str, message: str = "") -> None:
        self.action = action
        self.message = message or action
        super().__init__(self.message)


class ServiceNotEnabled(Exception):
    def __init__(self, service: str, message: str = "") -> None:
        self.service = service
        self.message = message or service
        super().__init__(self.message)


@dataclass(frozen=True)
class AzureIdentity:
    subscription_id: str
    tenant_id: str
    principal_name: str
    principal_id: str
    principal_type: str


def _require_azure() -> None:
    try:
        import azure.identity  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "Azure collectors require optional dependencies. Install with:\n"
            "  pip install 'ventra[azure]'"
        ) from exc


class AzureClientFactory:
    """Lazy Azure SDK clients bound to one subscription."""

    def __init__(self, subscription_id: str | None = None) -> None:
        _require_azure()
        from azure.identity import DefaultAzureCredential

        self.subscription_id = (
            subscription_id
            or os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
            or ""
        )
        self._credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
        self._clients: dict[str, Any] = {}
        self._graph_token: str | None = None

    def identity(self) -> AzureIdentity:
        from azure.mgmt.resource import SubscriptionClient

        sub_id = self.subscription_id
        if not sub_id:
            raise RuntimeError(
                "No Azure subscription id. Pass --subscription or set AZURE_SUBSCRIPTION_ID."
            )
        sub_client = SubscriptionClient(self._credential)
        sub = sub_client.subscriptions.get(sub_id)
        tenant_id = getattr(sub, "tenant_id", "") or ""
        principal_name = os.environ.get("AZURE_USERNAME", "") or os.environ.get("USER", "")
        principal_id = os.environ.get("AZURE_CLIENT_ID", "") or principal_name
        return AzureIdentity(
            subscription_id=sub_id,
            tenant_id=tenant_id,
            principal_name=principal_name,
            principal_id=principal_id,
            principal_type="User",
        )

    def enabled_regions(self) -> list[str]:
        from azure.mgmt.resource import SubscriptionClient

        sub_client = SubscriptionClient(self._credential)
        return sorted(
            loc.name
            for loc in sub_client.subscriptions.list_locations(self.subscription_id)
            if getattr(loc, "name", None)
        )

    def _client(self, key: str, factory: Any) -> Any:
        if key not in self._clients:
            self._clients[key] = factory()
        return self._clients[key]

    def monitor(self) -> Any:
        from azure.mgmt.monitor import MonitorManagementClient

        sub = self.subscription_id
        return self._client(
            "monitor",
            lambda: MonitorManagementClient(self._credential, sub),
        )

    def network(self) -> Any:
        from azure.mgmt.network import NetworkManagementClient

        sub = self.subscription_id
        return self._client(
            "network",
            lambda: NetworkManagementClient(self._credential, sub),
        )

    def security(self) -> Any:
        from azure.mgmt.security import SecurityCenter

        sub = self.subscription_id
        return self._client(
            "security",
            lambda: SecurityCenter(self._credential, sub, asc_location="centralus"),
        )

    def authorization(self) -> Any:
        from azure.mgmt.authorization import AuthorizationManagementClient

        sub = self.subscription_id
        return self._client(
            "authorization",
            lambda: AuthorizationManagementClient(self._credential, sub),
        )

    def graph_token(self) -> str:
        if self._graph_token is None:
            self._graph_token = self._credential.get_token(GRAPH_SCOPE).token
        return self._graph_token

    def graph_pages(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        max_records: int = 200_000,
    ) -> Iterator[dict[str, Any]]:
        return graph_get_pages(
            self.graph_token(),
            path,
            params=params,
            max_records=max_records,
        )

    def list_activity_logs(
        self,
        *,
        since: datetime,
        until: datetime,
        max_records: int = 200_000,
    ) -> list[dict[str, Any]]:
        start = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = until.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        filt = f"eventTimestamp ge '{start}' and eventTimestamp le '{end}'"
        out: list[dict[str, Any]] = []
        try:
            for item in self.monitor().activity_logs.list(filter=filt):
                out.append(to_dict(item))
                if len(out) >= max_records:
                    break
        except Exception as exc:
            msg = str(exc)
            if "AuthorizationFailed" in msg or "403" in msg:
                raise AccessDenied("Microsoft.Insights/ActivityLogs/read", msg) from exc
            raise
        return out
