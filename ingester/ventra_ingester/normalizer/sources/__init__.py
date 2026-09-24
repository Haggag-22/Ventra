"""Importing this package registers every source normalizer."""

from . import (
    access_logs,  # noqa: F401
    azure_activity_log,  # noqa: F401
    azure_diagnostics,  # noqa: F401
    azure_entra,  # noqa: F401
    azure_nsg_flow,  # noqa: F401
    cloudtrail,  # noqa: F401
    cloudwatch,  # noqa: F401
    dns_logs,  # noqa: F401
    eks_audit,  # noqa: F401
    findings,  # noqa: F401
    gcp_audit,  # noqa: F401
    gcp_findings,  # noqa: F401
    k8s_apiserver_audit,  # noqa: F401
    k8s_events,  # noqa: F401
    k8s_logs,  # noqa: F401
    k8s_state,  # noqa: F401
    log_analytics,  # noqa: F401
    m365,  # noqa: F401
    network,  # noqa: F401
    waf,  # noqa: F401
)
