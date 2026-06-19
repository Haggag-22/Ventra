"""Cloud Audit Logs — Admin Activity."""

from ..common.logging_collector import GcpLoggingCollector


class CloudAuditAdminCollector(GcpLoggingCollector):
    name = "cloud_audit_admin"
    priority = 1
    description = "Cloud Audit Logs — Admin Activity (management plane API calls)."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"cloudaudit.googleapis.com%2Factivity"'
