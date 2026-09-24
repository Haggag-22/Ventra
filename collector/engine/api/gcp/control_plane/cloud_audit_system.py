"""Cloud Audit Logs — System Event."""

from ..common.logging_collector import GcpLoggingCollector


class CloudAuditSystemCollector(GcpLoggingCollector):
    name = "cloud_audit_system"
    priority = 1
    description = "Cloud Audit Logs — System Event (VM and system changes)."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"cloudaudit.googleapis.com%2Fsystem_event"'
