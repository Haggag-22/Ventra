"""VPC Firewall rule logs."""

from ..common.logging_collector import GcpLoggingCollector


class FirewallLogsCollector(GcpLoggingCollector):
    name = "firewall_logs"
    priority = 1
    description = "Firewall Rules Logging for VPC firewall rule hits."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"compute.googleapis.com%2Ffirewall"'
    default_window_days = 14
