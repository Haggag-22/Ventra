"""Cloud DNS query log collector."""

from ..common.logging_collector import GcpLoggingCollector


class CloudDnsCollector(GcpLoggingCollector):
    name = "cloud_dns"
    priority = 2
    description = "Cloud DNS query and response logs from Cloud Logging."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'resource.type="dns_query"'
    default_window_days = 7
