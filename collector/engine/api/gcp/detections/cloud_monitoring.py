"""Cloud Monitoring alert policies and incidents."""

from ..common.logging_collector import GcpLoggingCollector


class CloudMonitoringCollector(GcpLoggingCollector):
    name = "cloud_monitoring"
    priority = 2
    description = "Cloud Monitoring alert and incident notification logs."
    required_actions = ("logging.logEntries.list", "monitoring.alertPolicies.list")
    log_filter = (
        'logName:("monitoring.googleapis.com" OR "alerting.googleapis.com") '
        'OR resource.type="global" AND severity>=WARNING'
    )
    default_window_days = 30
