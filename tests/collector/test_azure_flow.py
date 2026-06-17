"""Azure VNet / NSG flow-log collectors + tuple flattening + normalizer."""

from __future__ import annotations

from pathlib import Path

from collector.azure.client_factory import AzureAccessDenied
from collector.azure.network.flow_common import flatten_nsg_record, flatten_vnet_record
from collector.azure.network.nsg_flow import NsgFlowCollector
from collector.azure.network.vnet_flow import VNetFlowCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow

from ventra_ingester.normalizer.base import NormalizeContext
from ventra_ingester.normalizer.sources.azure_nsg_flow import normalize_vnet_flow

# A public dst with >1MB egress = the exfil signal.
NSG_BLOB = {
    "resourceId": "/SUBSCRIPTIONS/S1/.../NETWORKSECURITYGROUPS/web-nsg",
    "properties": {
        "Version": 2,
        "flows": [
            {"rule": "AllowOutbound", "flows": [
                {"mac": "00", "flowTuples": [
                    "1717808400,10.0.1.4,203.0.113.7,49152,443,T,O,A,E,9,1500,12,5000000",
                    "1717808405,10.0.1.4,198.51.100.9,50000,22,T,O,D,E,1,40,0,0",
                ]},
            ]},
        ],
    },
}
VNET_BLOB = {
    "resourceId": "/SUBSCRIPTIONS/S1/.../FLOWLOGS/fl1",
    "properties": {
        "Version": 4,
        "flowRecords": {"flows": [
            {"aclID": "/SUBSCRIPTIONS/S1/.../VIRTUALNETWORKS/prod-vnet", "flowGroups": [
                {"rule": "rule1", "flowTuples": [
                    "1717808400,10.0.2.4,185.220.101.45,49152,443,6,O,E,NX,9,1500,12,9000000",
                ]},
            ]},
        ]},
    },
}


class _FakeCf:
    def __init__(self, *, flow_logs=None, blobs=None, discover_error=None) -> None:
        self._flow_logs = flow_logs or {}
        self._blobs = blobs or []
        self._discover_error = discover_error

    def network_flow_logs(self, subscription_id):  # noqa: ANN001
        if self._discover_error is not None:
            raise self._discover_error
        return self._flow_logs.get(subscription_id, [])

    def container_client(self, storage_id, container):  # noqa: ANN001
        return object()  # opaque; read happens via the patched transport


def _ctx(tmp_path: Path, cf: _FakeCf) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="azure", account_id="tenant-abc", regions=[], time_window=TimeWindow(),
        staging=staging, case_id="CASE-AZ", tenant_id="tenant-abc",
        subscription_ids=["S1"], client_factory=cf,
    )


# -- tuple flattening --------------------------------------------------------------------

def test_flatten_nsg_v2_tuple() -> None:
    rows = list(flatten_nsg_record(NSG_BLOB))
    assert len(rows) == 2
    allow, deny = rows
    assert allow["srcaddr"] == "10.0.1.4" and allow["dstaddr"] == "203.0.113.7"
    assert allow["dstport"] == 443 and allow["action"] == "ALLOW"
    assert allow["bytes"] == 1500 + 5000000
    assert allow["timestamp"].startswith("2024-")  # epoch decoded
    assert deny["action"] == "DENY" and deny["dstport"] == 22


def test_flatten_vnet_v4_tuple() -> None:
    rows = list(flatten_vnet_record(VNET_BLOB))
    assert len(rows) == 1
    r = rows[0]
    assert r["srcaddr"] == "10.0.2.4" and r["dstaddr"] == "185.220.101.45"
    assert r["dstport"] == 443 and r["action"] == "ALLOW"
    assert r["bytes"] == 1500 + 9000000
    assert "VIRTUALNETWORKS/prod-vnet" in r["resource_id"]


# -- collectors --------------------------------------------------------------------------

def test_vnet_flow_collects(tmp_path: Path, monkeypatch) -> None:
    cf = _FakeCf(flow_logs={"S1": [
        {"name": "fl1", "target_resource_id": "/.../virtualNetworks/prod-vnet",
         "storage_id": "/.../storageAccounts/logs", "enabled": True, "flow_type": "vnet"},
    ]})
    monkeypatch.setattr(
        "collector.azure.network.flow_common.read_log_records", lambda cc, **k: iter([VNET_BLOB])
    )
    result = VNetFlowCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


def test_nsg_flow_no_flow_logs_is_a_gap(tmp_path: Path) -> None:
    cf = _FakeCf(flow_logs={"S1": []})
    result = NsgFlowCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)


def test_flow_discovery_access_denied_is_a_gap(tmp_path: Path) -> None:
    cf = _FakeCf(discover_error=AzureAccessDenied("network:flow_logs", "no reader role"))
    result = VNetFlowCollector(_ctx(tmp_path, cf)).collect()
    assert any(g[1] == GapReason.ACCESS_DENIED for g in result.gaps)


# -- normalizer --------------------------------------------------------------------------

def test_vnet_flow_normalizer_tags_source_and_egress() -> None:
    ctx = NormalizeContext(case_id="CASE-AZ", account_id="tenant-abc")
    flat = next(iter(flatten_vnet_record(VNET_BLOB)))
    ev = next(iter(normalize_vnet_flow([flat], ctx)))
    assert ev.ventra_source == "vnet_flow"
    assert ev.dest_ip == "185.220.101.45"
    assert ev.event_severity == "medium"  # public dst, >1MB
