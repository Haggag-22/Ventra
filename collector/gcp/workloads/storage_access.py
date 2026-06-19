"""Cloud Storage bucket access logs."""

from ..common.logging_collector import GcpLoggingCollector


class StorageAccessCollector(GcpLoggingCollector):
    name = "storage_access"
    priority = 1
    description = "Cloud Storage bucket access and data-plane audit logs."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"storage.googleapis.com%2Frequests"'
    default_window_days = 30
