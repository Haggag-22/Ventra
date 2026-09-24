"""Cloud SQL query, connection, and error logs."""

from ..common.logging_collector import GcpLoggingCollector


class CloudSqlCollector(GcpLoggingCollector):
    name = "cloud_sql"
    priority = 1
    description = "Cloud SQL query, connection, slow query, and error logs from Cloud Logging."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'resource.type="cloudsql_database"'
    default_window_days = 14
