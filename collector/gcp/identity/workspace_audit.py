"""Google Workspace / Cloud Identity group audit events."""

from ..common.logging_collector import GcpLoggingCollector


class WorkspaceAuditCollector(GcpLoggingCollector):
    name = "workspace_audit"
    priority = 2
    description = "Google Workspace group and directory audit events (when routed to Cloud Logging)."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'logName:("cloudaudit.googleapis.com%2Factivity" OR "admin.googleapis.com") '
        'AND (protoPayload.serviceName="admin.googleapis.com" '
        'OR protoPayload.serviceName="cloudidentity.googleapis.com")'
    )
