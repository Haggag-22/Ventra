"""Azure normalizers must read the field names the collectors actually write."""

from ventra_ingester.normalizer.base import NormalizeContext
from ventra_ingester.normalizer.sources.azure_activity_log import normalize_activity_log
from ventra_ingester.normalizer.sources.azure_diagnostics import (
    normalize_app_gateway,
    normalize_key_vault,
    normalize_storage_access,
)

CTX = NormalizeContext(case_id="AZ", account_id="tenant")


def test_activity_log_reads_sdk_snake_case() -> None:
    rec = {
        "operation_name": {
            "value": "Microsoft.Storage/storageAccounts/listKeys/action",
            "localized_value": "List keys",
        },
        "event_timestamp": "2026-10-04T09:00:16Z",
        "caller": "user@example.com",
        "claims": {"ipaddr": "203.0.113.10"},
        "resource_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
        "status": {"value": "Succeeded"},
        "subscription_id": "sub",
    }
    ev = next(normalize_activity_log([rec], CTX))
    assert ev.event_action == "Microsoft.Storage/storageAccounts/listKeys/action"
    assert ev.timestamp == "2026-10-04T09:00:16Z"
    assert ev.source_ip == "203.0.113.10"
    assert ev.message.startswith("List keys on /subscriptions/sub/")


def test_activity_log_reads_storage_archive_shape() -> None:
    rec = {
        "time": "2026-06-08T01:05:00Z",
        "operationName": "Microsoft.Compute/virtualMachines/delete",
        "resultType": "Failure",
        "callerIpAddress": "203.0.113.7",
        "resourceId": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
        "identity": {"claims": {"name": "attacker@corp.com"}},
        "subscriptionId": "sub-1",
    }
    ev = next(normalize_activity_log([rec], CTX))
    assert ev.timestamp == "2026-06-08T01:05:00Z"
    assert ev.event_action == "Microsoft.Compute/virtualMachines/delete"
    assert ev.event_outcome == "failure"
    assert ev.user_name == "attacker@corp.com"
    assert ev.source_ip == "203.0.113.7"


def test_storage_access_reads_top_level_operation_and_object() -> None:
    rec = {
        "time": "2026-10-04T07:21:26Z",
        "operationName": "GetBlob",
        "callerIpAddress": "74.213.236.65:65496",
        "uri": "https://acct.blob.core.windows.net/container/object.csv",
        "location": "eastus",
        "statusCode": 200,
        "identity": {"type": "AccountKey"},
        "properties": {"objectKey": "/acct/container/object.csv"},
        "resourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
    }
    ev = next(normalize_storage_access([rec], CTX))
    assert ev.event_action == "GetBlob"
    assert ev.source_ip == "74.213.236.65"
    assert ev.user_name == "AccountKey"
    assert ev.resource_id == "/acct/container/object.csv"
    assert ev.cloud_region == "eastus"
    assert ev.message == "GetBlob /acct/container/object.csv"


def test_key_vault_uses_operation_name_not_category() -> None:
    rec = {
        "time": "2026-10-04T07:58:04Z",
        "category": "AuditEvent",
        "operationName": "SecretGet",
        "callerIpAddress": "20.223.70.99",
        "identity": {"claim": {"appid": "app-1"}},
        "properties": {"id": "https://kv.vault.azure.net/secrets/demo"},
        "resourceId": "/subscriptions/sub/providers/Microsoft.KeyVault/vaults/kv",
    }
    ev = next(normalize_key_vault([rec], CTX))
    assert ev.event_action == "SecretGet"
    assert ev.source_ip == "20.223.70.99"
    assert ev.user_name == "app-1"
    assert "SecretGet" in ev.message
    assert "https://kv.vault.azure.net/secrets/demo" in ev.message


def test_app_gateway_access_and_waf_are_readable() -> None:
    access = {
        "time": "2026-10-04T07:44:36Z",
        "category": "ApplicationGatewayAccessLog",
        "properties": {
            "clientIP": "205.210.31.90",
            "httpMethod": "GET",
            "requestUri": "/health",
            "httpStatus": 200,
            "error_info": "ERRORINFO_NO_ERROR",
        },
    }
    waf = {
        "time": "2026-10-04T07:44:36Z",
        "category": "ApplicationGatewayFirewallLog",
        "properties": {
            "clientIp": "45.198.224.125",
            "requestUri": "/",
            "ruleId": "920350",
            "action": "Matched",
            "message": "Host header is a numeric IP address",
        },
    }
    access_ev = next(normalize_app_gateway([access], CTX))
    waf_ev = next(normalize_app_gateway([waf], CTX))
    assert access_ev.event_action == "GET"
    assert "GET /health → 200" in access_ev.message
    assert "ERRORINFO_NO_ERROR" not in access_ev.message
    assert waf_ev.event_action == "Matched"
    assert waf_ev.source_ip == "45.198.224.125"
    assert "920350" in waf_ev.message
