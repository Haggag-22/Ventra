"""Log Analytics collection constants — diagnostic categories routed to LA workspaces."""

from __future__ import annotations

# Catalog source id → ARM resource types + AzureDiagnostics Category values.
LA_SOURCE_SPECS: dict[str, dict[str, list[str]]] = {
    "azure_firewall": {
        "resource_types": ["Microsoft.Network/azureFirewalls"],
        "categories": [
            "AzureFirewallApplicationRule",
            "AzureFirewallNetworkRule",
            "AzureFirewallDnsProxy",
        ],
    },
    "app_gateway": {
        "resource_types": ["Microsoft.Network/applicationGateways"],
        "categories": [
            "ApplicationGatewayAccessLog",
            "ApplicationGatewayPerformanceLog",
            "ApplicationGatewayFirewallLog",
        ],
    },
    "front_door": {
        "resource_types": ["Microsoft.Network/frontDoors", "Microsoft.Cdn/profiles"],
        "categories": ["FrontDoorAccessLog", "FrontDoorWebApplicationFirewallLog"],
    },
    "dns": {
        "resource_types": [
            "Microsoft.Network/dnsZones",
            "Microsoft.Network/privateDnsZones",
            "Microsoft.Network/dnsResolverEndpoints",
        ],
        "categories": ["AzureDnsQueryLogs", "QueryLogs", "DNSQueryLogs"],
    },
    "storage_access": {
        "resource_types": ["Microsoft.Storage/storageAccounts"],
        "categories": ["StorageRead", "StorageWrite", "StorageDelete"],
    },
    "key_vault": {
        "resource_types": ["Microsoft.KeyVault/vaults"],
        "categories": ["AuditEvent"],
    },
    "aks_audit": {
        "resource_types": ["Microsoft.ContainerService/managedClusters"],
        "categories": ["kube-audit", "kube-audit-admin"],
    },
}

DEFAULT_WINDOW_DAYS = 7
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS

CATEGORY_TO_SOURCE: dict[str, str] = {
    cat: source
    for source, spec in LA_SOURCE_SPECS.items()
    for cat in spec["categories"]
}

PERMISSION_NOTE = (
    "Requires Microsoft.OperationalInsights/workspaces/read and "
    "Microsoft.OperationalInsights/workspaces/query/action on each workspace."
)
