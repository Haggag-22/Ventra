"""BigQuery data access audit logs."""

from ..common.logging_collector import GcpLoggingCollector


class BigQueryAuditCollector(GcpLoggingCollector):
    name = "bigquery_audit"
    priority = 1
    description = "BigQuery data access audit logs from Cloud Logging."
    required_actions = ("logging.logEntries.list",)
    # The bigquery.googleapis.com serviceName view over the shared data_access stream.
    # Kept strictly a subset of that stream so dedup can serve it from the broad read.
    log_filter = (
        'logName:"cloudaudit.googleapis.com%2Fdata_access" '
        'AND protoPayload.serviceName="bigquery.googleapis.com"'
    )
    default_window_days = 30
