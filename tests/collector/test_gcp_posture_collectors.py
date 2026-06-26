"""Unit tests for GCP GCE, network posture, and logging posture collectors."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from collector.engine.api.gcp.control_plane.logging_posture import LoggingPostureCollector
from collector.engine.api.gcp.identity.iam_policy import IamPolicyCollector
from collector.engine.api.gcp.network.network_posture import NetworkPostureCollector
from collector.engine.api.gcp.workloads.gce import GceCollector
from collector.engine.api.gcp.workloads.bigquery_audit import BigQueryAuditCollector
from collector.engine.api.gcp.workloads.cloud_sql import CloudSqlCollector
from collector.engine.api.gcp.workloads.secret_manager import SecretManagerCollector
from collector.engine.api.gcp.network.cloud_armor import CloudArmorCollector
from collector.engine.api.gcp.network.cloud_dns import CloudDnsCollector
from collector.engine.api.gcp.network.cloud_nat import CloudNatCollector
from collector.engine.api.gcp.workloads.gke_audit import GkeAuditCollector
from collector.lib.models import CollectionContext, GapReason, SourceStatus, TimeWindow


def _ctx(tmp_path: Path, *, projects: list[str] | None = None) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir()
    ctx = CollectionContext(
        cloud="gcp",
        staging=staging,
        case_id="CASE-GCP",
        account_id="org-123",
        regions=[],
        time_window=TimeWindow(),
    )
    ctx.project_ids = projects or ["demo-project"]
    ctx.client_factory = MagicMock()
    return ctx


def test_iam_policy_collector_snapshot(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.iam_policy_snapshot.return_value = {
        "project_id": "demo-project",
        "bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}],
        "etag": "abc",
    }
    cf.list_service_accounts.return_value = [
        {
            "name": "projects/demo-project/serviceAccounts/sa@demo.iam.gserviceaccount.com",
            "email": "sa@demo.iam.gserviceaccount.com",
        }
    ]
    cf.list_service_account_keys.return_value = [
        {
            "name": "projects/demo-project/serviceAccounts/sa@demo.iam.gserviceaccount.com/keys/k1",
            "keyType": "USER_MANAGED",
            "disabled": False,
        }
    ]
    cf.service_account_iam_policy.return_value = {
        "bindings": [{"role": "roles/iam.serviceAccountUser", "members": ["user:bob@example.com"]}],
        "etag": "def",
    }
    cf.list_project_custom_roles.return_value = [
        {"name": "projects/demo-project/roles/customViewer", "title": "Custom viewer"}
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = IamPolicyCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    payload = json.loads((tmp_path / "staging" / "sources" / "iam_policy" / "snapshot.json").read_text())
    project = payload["projects"][0]
    assert project["bindings"][0]["role"] == "roles/viewer"
    assert len(project["service_accounts"]) == 1
    assert project["service_accounts"][0]["keys"][0]["keyType"] == "USER_MANAGED"
    assert project["custom_roles"][0]["title"] == "Custom viewer"


def test_iam_policy_collector_empty_project(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.project_ids = []
    result = IamPolicyCollector(ctx).collect()
    assert result.status == SourceStatus.EMPTY


def test_gce_collector_inventory(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.compute_aggregated_instances.return_value = [
        {
            "id": "123",
            "name": "web-1",
            "zone": "zones/us-central1-a",
            "tags": {"items": ["http-server"]},
            "serviceAccounts": [{"email": "sa@demo.iam.gserviceaccount.com"}],
            "metadata": {"items": [{"key": "startup-script", "value": "secret"}]},
            "networkInterfaces": [{"name": "nic0", "network": "default"}],
        }
    ]
    cf.compute_aggregated_disks.return_value = [{"id": "disk-1", "name": "boot"}]
    cf.compute_snapshots.return_value = [{"id": "snap-1", "name": "backup"}]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = GceCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 4
    payload = json.loads((tmp_path / "staging" / "sources" / "gce" / "snapshot.json").read_text())
    assert payload["instances"][0]["_ventra_metadata_keys"] == ["startup-script"]
    assert payload["instances"][0]["metadata"]["items"] == [{"key": "startup-script"}]
    assert len(payload["network_interfaces"]) == 1
    cf.compute_aggregated_instances.assert_called_once()


def test_gce_collector_empty_project(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, projects=[])
    result = GceCollector(ctx).collect()
    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.NOT_PRESENT for g in result.gaps)


def test_gce_collector_access_denied(tmp_path: Path) -> None:
    from collector.clouds.gcp.client_factory import GcpAccessDenied

    cf = MagicMock()
    cf.compute_aggregated_instances.side_effect = GcpAccessDenied("denied")
    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = GceCollector(ctx).collect()
    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.ACCESS_DENIED for g in result.gaps)


def test_network_posture_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.compute_firewalls.return_value = [{"name": "allow-ssh", "direction": "INGRESS"}]
    cf.compute_networks.return_value = [{"name": "default", "peerings": []}]
    cf.compute_subnetworks.return_value = [
        {"name": "default-us-central1", "logConfig": {"enable": True}}
    ]
    cf.compute_routes.return_value = [{"name": "default-route"}]
    cf.compute_packet_mirrorings.return_value = [{"name": "mirror-1"}]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = NetworkPostureCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    payload = json.loads(
        (tmp_path / "staging" / "sources" / "network_posture" / "snapshot.json").read_text()
    )
    assert len(payload["firewall_rules"]) == 1
    assert len(payload["subnetworks"]) == 1
    assert payload["subnetworks"][0]["_ventra_project_id"] == "demo-project"


def test_logging_posture_flow_logs_gap(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.compute_subnetworks.return_value = [
        {"name": "subnet-a", "logConfig": {"enable": False}},
        {"name": "subnet-b"},
    ]
    cf.compute_firewalls.return_value = [{"name": "allow-all", "logConfig": {"enable": True}}]
    cf.list_log_sinks.return_value = [
        {
            "name": "audit-sink",
            "destination": "storage.googleapis.com/bucket",
            "filter": 'logName:"cloudaudit.googleapis.com"',
        }
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = LoggingPostureCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    gap_reasons = {g[0]: g[1] for g in result.gaps}
    assert gap_reasons["vpc_flow_logs"] == GapReason.LOGGING_NOT_CONFIGURED
    assert gap_reasons["firewall_rule_logging"] == GapReason.OUT_OF_SCOPE
    assert gap_reasons["audit_log_sinks"] == GapReason.OUT_OF_SCOPE


def test_filter_gce_inventory_by_zone() -> None:
    from collector.lib.scoping import filter_gce_inventory

    inventory = {
        "instances": [
            {"id": "1", "_ventra_zone": "us-central1-a", "networkInterfaces": []},
            {"id": "2", "_ventra_zone": "europe-west1-b", "networkInterfaces": []},
        ],
        "disks": [],
        "snapshots": [],
        "network_interfaces": [],
    }
    filtered = filter_gce_inventory(inventory, {"zones": ["us-central1-a"]})
    assert len(filtered["instances"]) == 1
    assert filtered["instances"][0]["id"] == "1"


def test_gke_audit_collector_with_logs(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_gke_clusters.return_value = [
        {
            "name": "prod",
            "location": "us-central1",
            "loggingConfig": {"componentConfig": {"enableComponents": ["APISERVER"]}},
        }
    ]
    cf.list_log_entries.return_value = [
        {"logName": "projects/demo/logs/container", "jsonPayload": {"verb": "create"}}
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = GkeAuditCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    config = json.loads((tmp_path / "staging" / "sources" / "gke_audit" / "config.json").read_text())
    assert config["audit_enabled_count"] == 1


def test_gke_audit_collector_logging_gap(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_gke_clusters.return_value = [
        {"name": "silent", "location": "us-central1", "loggingService": "none"}
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = GkeAuditCollector(ctx).collect()

    assert result.status == SourceStatus.EMPTY
    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)
    cf.list_log_entries.assert_not_called()


def test_cloud_dns_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_log_entries.return_value = [
        {"resource": {"type": "dns_query"}, "jsonPayload": {"queryName": "example.com."}}
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = CloudDnsCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    _, kwargs = cf.list_log_entries.call_args
    assert 'resource.type="dns_query"' in kwargs["log_filter"]


def test_cloud_nat_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_log_entries.return_value = [
        {
            "resource": {"type": "nat_gateway", "labels": {"gateway_name": "egress-nat"}},
            "jsonPayload": {"connection": {"src_ip": "10.0.0.5", "dest_ip": "203.0.113.1"}},
        }
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    ctx.artifact_parameters = {
        "cloud_nat": {
            "nat_gateway_names": ["egress-nat"],
            "dest_ip": ["203.0.113.1"],
        }
    }
    result = CloudNatCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    _, kwargs = cf.list_log_entries.call_args
    assert 'resource.type="nat_gateway"' in kwargs["log_filter"]
    assert 'compute.googleapis.com%2Fnat_flows' in kwargs["log_filter"]
    assert 'resource.labels.gateway_name="egress-nat"' in kwargs["log_filter"]
    assert 'jsonPayload.connection.dest_ip="203.0.113.1"' in kwargs["log_filter"]


def test_bigquery_audit_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_log_entries.return_value = [
        {
            "protoPayload": {"serviceName": "bigquery.googleapis.com", "methodName": "jobservice.jobcompleted"},
            "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Fdata_access",
        }
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    ctx.artifact_parameters = {
        "bigquery_audit": {
            "dataset_ids": ["customer_data"],
            "table_ids": ["events"],
        }
    }
    result = BigQueryAuditCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    _, kwargs = cf.list_log_entries.call_args
    assert 'protoPayload.serviceName="bigquery.googleapis.com"' in kwargs["log_filter"]
    assert 'resource.type="bigquery_resource"' in kwargs["log_filter"]
    assert 'resource.labels.dataset_id="customer_data"' in kwargs["log_filter"]
    assert 'resource.labels.table_id="events"' in kwargs["log_filter"]


def test_cloud_sql_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_log_entries.return_value = [
        {
            "resource": {"type": "cloudsql_database", "labels": {"database_id": "prod-mysql"}},
            "textPayload": "2026-06-01 12:00:00 UTC [123]: LOG: connection authorized",
        }
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    ctx.artifact_parameters = {"cloud_sql": {"instance_names": ["prod-mysql"]}}
    result = CloudSqlCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    _, kwargs = cf.list_log_entries.call_args
    assert 'resource.type="cloudsql_database"' in kwargs["log_filter"]
    assert 'resource.labels.database_id="prod-mysql"' in kwargs["log_filter"]


def test_secret_manager_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.list_log_entries.return_value = [
        {
            "protoPayload": {
                "serviceName": "secretmanager.googleapis.com",
                "methodName": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
            },
            "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Fdata_access",
        }
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    ctx.artifact_parameters = {"secret_manager": {"secret_names": ["api-key"]}}
    result = SecretManagerCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    _, kwargs = cf.list_log_entries.call_args
    assert 'protoPayload.serviceName="secretmanager.googleapis.com"' in kwargs["log_filter"]
    assert 'cloudaudit.googleapis.com%2Fdata_access' in kwargs["log_filter"]
    assert 'resource.labels.secret_id="api-key"' in kwargs["log_filter"]


def test_cloud_armor_collector(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.compute_security_policies.return_value = [{"name": "default-policy", "id": "123"}]
    cf.list_log_entries.return_value = [
        {"jsonPayload": {"enforcedSecurityPolicy": {"name": "default-policy"}}}
    ]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = CloudArmorCollector(ctx).collect()

    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1
    config = json.loads((tmp_path / "staging" / "sources" / "cloud_armor" / "config.json").read_text())
    assert len(config["security_policies"]) == 1


def test_cloud_armor_logging_gap(tmp_path: Path) -> None:
    cf = MagicMock()
    cf.compute_security_policies.return_value = [{"name": "default-policy", "id": "123"}]
    cf.list_log_entries.return_value = []

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    result = CloudArmorCollector(ctx).collect()

    assert any(g[1] == GapReason.LOGGING_NOT_CONFIGURED for g in result.gaps)
