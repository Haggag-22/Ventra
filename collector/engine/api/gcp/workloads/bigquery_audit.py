"""BigQuery data access audit logs."""

from ..common.logging_collector import GcpLoggingCollector


class BigQueryAuditCollector(GcpLoggingCollector):
    name = "bigquery_audit"
    priority = 1
    description = "BigQuery data access audit logs from Cloud Logging."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        '(protoPayload.serviceName="bigquery.googleapis.com" '
        'AND logName:"cloudaudit.googleapis.com%2Fdata_access") '
        'OR resource.type="bigquery_resource"'
    )
    default_window_days = 30
