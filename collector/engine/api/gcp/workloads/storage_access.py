"""Cloud Storage bucket access logs."""

from ..common.logging_collector import GcpLoggingCollector


class StorageAccessCollector(GcpLoggingCollector):
    name = "storage_access"
    priority = 1
    description = "Cloud Storage bucket access and data-plane audit logs."
    required_actions = ("logging.logEntries.list",)
    # Bucket data-plane access is the storage.googleapis.com serviceName view over the
    # shared data_access stream (a filter over that table, not a separate log).
    log_filter = (
        'logName:"cloudaudit.googleapis.com%2Fdata_access" '
        'AND protoPayload.serviceName="storage.googleapis.com"'
    )
    default_window_days = 30
