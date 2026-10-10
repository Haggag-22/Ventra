"""Azure identity mapping and already-ingested event repair for the investigation panels."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "backend"))

from app.store import CaseStore, EventQuery  # noqa: E402


def test_normalize_azure_identity_maps_directory_and_assignments() -> None:
    directory = {
        "users": [{"id": "user-1", "displayName": "Ada", "userPrincipalName": "ada@contoso.com"}],
        "groups": [],
        "applications": [{"id": "app-obj", "appId": "app-1", "displayName": "Ventra"}],
        "service_principals": [{"id": "sp-1", "displayName": "Graph", "appId": "app-9"}],
    }
    rbac = {
        "role_definitions": [
            {
                "id": "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/owner",
                "role_name": "Owner",
            }
        ],
        "role_assignments": [
            {
                "id": "/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/ra-1",
                "name": "ra-1",
                "role_definition_id": "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/owner",
                "principal_id": "user-1",
                "principal_type": "User",
                "scope": "/subscriptions/sub",
                "created_on": "2026-10-04T00:00:00Z",
            }
        ],
    }
    iam = CaseStore.normalize_azure_identity(directory, rbac)
    assert iam["source"] == "entra_directory"
    assert iam["mfa_known"] is False
    assert [u["UserName"] for u in iam["users"]] == ["ada@contoso.com"]
    assert iam["applications"][0]["principal_type"] == "Application"
    assert iam["service_principals"][0]["display_name"] == "Graph"
    assert iam["groups"] == []
    assert iam["roles"][0]["RoleName"] == "Owner"
    assert iam["roles"][0]["principal"] == "Ada"
    assert iam["roles"][0]["scope"] == "/subscriptions/sub"
    assert iam["role_definition_count"] == 1


def test_query_repairs_blank_azure_rows_from_raw(tmp_path: Path) -> None:
    case = tmp_path / "AZ"
    case.mkdir()
    (case / "summary.json").write_text(json.dumps({"case_id": "AZ", "cloud": "azure"}))
    activity = {
        "operation_name": {
            "value": "Microsoft.Storage/storageAccounts/listKeys/action",
            "localized_value": "List keys",
        },
        "event_timestamp": "2026-10-04T09:00:16Z",
        "caller": "user@example.com",
        "claims": {"ipaddr": "203.0.113.10"},
        "resource_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
    }
    storage = {
        "time": "2026-10-04T07:21:26Z",
        "operationName": "GetBlob",
        "callerIpAddress": "74.213.236.65:65496",
        "location": "eastus",
        "identity": {"type": "AccountKey"},
        "properties": {"objectKey": "/acct/customer-exports/sample.csv"},
    }
    vault = {
        "time": "2026-10-04T07:58:04Z",
        "category": "AuditEvent",
        "operationName": "SecretSet",
        "callerIpAddress": "20.223.70.99",
        "identity": {"claim": {"appid": "app-1"}},
        "properties": {"id": "https://kv.vault.azure.net/secrets/demo"},
        "resourceId": "/subscriptions/sub/providers/Microsoft.KeyVault/vaults/kv",
    }
    con = duckdb.connect()
    con.execute(
        """
        CREATE TABLE events (
          timestamp VARCHAR, event_action VARCHAR, message VARCHAR, user_name VARCHAR,
          source_ip VARCHAR, resource_id VARCHAR, cloud_region VARCHAR, cloud_service VARCHAR,
          ventra_source VARCHAR, raw VARCHAR, event_outcome VARCHAR, dest_bytes BIGINT,
          user_arn VARCHAR, resource_type VARCHAR
        )
        """
    )
    con.executemany(
        "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                "",
                "",
                " on /subscriptions/sub",
                "user@example.com",
                "",
                "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
                "",
                "azure",
                "activity_log",
                json.dumps(activity),
                "success",
                0,
                "",
                "",
            ),
            (
                "",
                "",
                " on tenant",
                "",
                "",
                "",
                "",
                "",
                "storage_access",
                json.dumps(storage),
                "success",
                0,
                "",
                "",
            ),
            (
                "2026-10-04T07:58:04Z",
                "AuditEvent",
                "Key Vault AuditEvent",
                "",
                "",
                "/subscriptions/sub/providers/Microsoft.KeyVault/vaults/kv",
                "",
                "keyvault",
                "key_vault",
                json.dumps(vault),
                "success",
                0,
                "",
                "",
            ),
        ],
    )
    con.execute(f"COPY events TO '{case / 'events.parquet'}' (FORMAT PARQUET)")

    store = CaseStore(root=tmp_path)
    activity_rows = store.query_events("AZ", EventQuery(sources=["activity_log"], limit=5))
    row = activity_rows["events"][0]
    assert row["event_action"] == "Microsoft.Storage/storageAccounts/listKeys/action"
    assert row["timestamp"] == "2026-10-04T09:00:16Z"
    assert row["message"].startswith("List keys on ")
    assert row["source_ip"] == "203.0.113.10"

    storage_rows = store.query_events("AZ", EventQuery(sources=["storage_access"], limit=5))
    stored = storage_rows["events"][0]
    assert stored["event_action"] == "GetBlob"
    assert stored["source_ip"] == "74.213.236.65"
    assert stored["user_name"] == "AccountKey"
    assert stored["resource_id"] == "/acct/customer-exports/sample.csv"
    assert stored["cloud_region"] == "eastus"

    overview = store.data_access_overview("AZ")
    ops = {item["op"]: item["count"] for item in overview["operations"]}
    assert ops.get("read") == 1
    assert ops.get("write") == 1
    assert "other" not in ops
    objects = {item["resource_id"] for item in overview["top_objects"]}
    assert "/acct/customer-exports/sample.csv" in objects
    sources = {item["source"] for item in overview["by_source"]}
    assert sources == {"storage_access", "key_vault"}
