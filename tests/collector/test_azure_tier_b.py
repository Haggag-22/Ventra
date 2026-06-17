"""Tier B+ Azure collectors: defender, RBAC, subscription, diagnostics, AKS audit.

Uses a fake client factory (no Azure credentials) mirroring test_azure_tier_a.py.
"""

from __future__ import annotations

from pathlib import Path

from collector.azure.client_factory import AzureAccessDenied
from collector.azure.detections.defender import DefenderCollector
from collector.azure.identity.rbac import RbacCollector
from collector.azure.identity.subscription import SubscriptionCollector
from collector.azure.network.azure_firewall import AzureFirewallCollector
from collector.azure.workloads.aks_audit import AksAuditCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow


class _FakeCf:
    def __init__(
        self,
        *,
        alerts: dict[str, list[dict]] | None = None,
        rbac: dict[str, dict] | None = None,
        subscriptions: list[dict] | None = None,
        resources: dict[str, list[dict]] | None = None,
        diagnostics: dict[str, list[dict]] | None = None,
        clusters: dict[str, list[dict]] | None = None,
        blobs: dict[tuple[str, str], list[dict]] | None = None,
        identity=None,
    ) -> None:
        self._alerts = alerts or {}
        self._rbac = rbac or {}
        self._subscriptions = subscriptions
        self._resources = resources or {}
        self._diagnostics = diagnostics or {}
        self._clusters = clusters or {}
        self._blobs = blobs or {}
        self._identity = identity

    def caller_identity(self):
        if self._identity:
            return self._identity
        from collector.azure.client_factory import AzureIdentity

        return AzureIdentity(tenant_id="tenant-abc", principal="sp-123", tenant_name="Contoso")

    def subscription_details(self):
        if self._subscriptions is not None:
            return self._subscriptions
        return [
            {
                "subscription_id": "sub-1",
                "display_name": "Prod",
                "tenant_id": "tenant-abc",
                "state": "Enabled",
            }
        ]

    def security_alerts(self, subscription_id, *, max_records=200_000):
        yield from self._alerts.get(subscription_id, [])

    def rbac_snapshot(self, subscription_id):
        return self._rbac.get(
            subscription_id,
            {"role_definitions": [{"roleName": "Reader"}], "role_assignments": [{"principalId": "p1"}]},
        )

    def resources_of_type(self, subscription_id, resource_types):
        key = f"{subscription_id}:{','.join(resource_types)}"
        return self._resources.get(key, self._resources.get(subscription_id, []))

    def diagnostic_settings(self, resource_id):
        return self._diagnostics.get(resource_id, [])

    def managed_clusters(self, subscription_id):
        return self._clusters.get(subscription_id, [])

    def container_client(self, storage_id, container):
        return _FakeContainer(self._blobs.get((storage_id, container), []))


class _FakeContainer:
    def __init__(self, records: list[dict]) -> None:
        self._records = records

    def list_blobs(self, name_starts_with=None):
        del name_starts_with
        yield type("Blob", (), {"name": "PT1H.json"})()

    def download_blob(self, name):
        del name
        import json

        payload = json.dumps({"records": self._records}).encode()

        class _DL:
            def readall(self):
                return payload

        return _DL()


def _ctx(tmp_path: Path, cf: _FakeCf, *, subscriptions: list[str] | None = None) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="azure",
        account_id="tenant-abc",
        regions=[],
        time_window=TimeWindow(),
        staging=staging,
        case_id="CASE-AZ",
        tenant_id="tenant-abc",
        subscription_ids=subscriptions or ["sub-1"],
        client_factory=cf,
    )


def test_defender_collects_alerts(tmp_path: Path) -> None:
    cf = _FakeCf(
        alerts={
            "sub-1": [
                {"properties": {"alertDisplayName": "Suspicious login", "severity": "High"}}
            ]
        }
    )
    result = DefenderCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


def test_subscription_snapshot(tmp_path: Path) -> None:
    cf = _FakeCf(
        subscriptions=[
            {"subscription_id": "sub-1", "display_name": "Prod", "tenant_id": "t", "state": "Enabled"}
        ]
    )
    result = SubscriptionCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert any(f.path.endswith("snapshot.json") for f in result.files)


def test_rbac_snapshot(tmp_path: Path) -> None:
    cf = _FakeCf(rbac={"sub-1": {"role_definitions": [{"roleName": "Owner"}], "role_assignments": []}})
    result = RbacCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED


def test_rbac_access_denied_is_a_gap(tmp_path: Path) -> None:
    class _DeniedCf(_FakeCf):
        def rbac_snapshot(self, subscription_id):
            raise AzureAccessDenied("rbac", "forbidden")

    result = RbacCollector(_ctx(tmp_path, _DeniedCf())).collect()
    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.ACCESS_DENIED for g in result.gaps)


def test_azure_firewall_diagnostic_collects(tmp_path: Path) -> None:
    rid = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw1"
    cf = _FakeCf(
        resources={"sub-1": [{"id": rid, "name": "fw1"}]},
        diagnostics={
            rid: [{"storage_account_id": "sa1", "categories": ["AzureFirewallNetworkRule"]}]
        },
        blobs={
            ("sa1", "insights-logs-azurefirewallnetworkrule"): [
                {"time": "2026-06-08T01:00:00Z", "properties": {"msg": "deny", "srcIp": "10.0.0.1"}}
            ]
        },
    )
    result = AzureFirewallCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 1
    assert result.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)


def test_azure_firewall_no_diagnostic_is_a_gap(tmp_path: Path) -> None:
    rid = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw1"
    cf = _FakeCf(resources={"sub-1": [{"id": rid, "name": "fw1"}]}, diagnostics={rid: []})
    result = AzureFirewallCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 0
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_aks_audit_disabled_is_a_gap(tmp_path: Path) -> None:
    rid = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1"
    cf = _FakeCf(
        clusters={"sub-1": [{"id": rid, "name": "aks1", "location": "eastus", "properties": {}}]},
        diagnostics={rid: []},
    )
    result = AksAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 0
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_aks_audit_collects_from_storage(tmp_path: Path) -> None:
    rid = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1"
    cf = _FakeCf(
        clusters={"sub-1": [{"id": rid, "name": "aks1", "location": "eastus", "properties": {}}]},
        diagnostics={rid: [{"storage_account_id": "sa1", "categories": ["kube-audit"]}]},
        blobs={
            ("sa1", "insights-logs-kube-audit"): [
                {
                    "stage": "ResponseComplete",
                    "verb": "get",
                    "user": {"username": "admin"},
                    "objectRef": {"resource": "pods", "name": "nginx"},
                }
            ]
        },
    )
    result = AksAuditCollector(_ctx(tmp_path, cf)).collect()
    assert result.record_count == 1
    assert result.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)
