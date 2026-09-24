"""Secret Manager data access audit logs."""

from ..common.logging_collector import GcpLoggingCollector


class SecretManagerCollector(GcpLoggingCollector):
    name = "secret_manager"
    priority = 1
    description = "Secret Manager access audit logs from Cloud Logging Data Access."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'protoPayload.serviceName="secretmanager.googleapis.com" '
        'AND logName:"cloudaudit.googleapis.com%2Fdata_access"'
    )
    default_window_days = 30
