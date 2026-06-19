"""Cloud Load Balancer access logs."""

from ..common.logging_collector import GcpLoggingCollector


class LoadBalancerCollector(GcpLoggingCollector):
    name = "load_balancer"
    priority = 1
    description = "Cloud Load Balancer request logs (HTTP(S), TCP/UDP proxy)."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'logName:("compute.googleapis.com%2Frequests" '
        'OR "loadbalancing.googleapis.com%2Frequests")'
    )
    default_window_days = 14
