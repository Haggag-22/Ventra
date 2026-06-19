"""Cloud Audit Logs — Data Access (includes policy-denied bucket access)."""

from ..common.logging_collector import GcpLoggingCollector


class CloudAuditDataCollector(GcpLoggingCollector):
    name = "cloud_audit_data"
    priority = 1
    description = "Cloud Audit Logs — Data Access (read/write operations and policy denials)."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"cloudaudit.googleapis.com%2Fdata_access"'
