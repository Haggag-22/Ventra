"""Cloud Load Balancer access logs."""

from ..common.logging_collector import GcpLoggingCollector


class LoadBalancerCollector(GcpLoggingCollector):
    name = "load_balancer"
    priority = 1
    description = "Load Balancer Access Logs for HTTP(S) and TCP/UDP proxy load balancers."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'logName:("compute.googleapis.com%2Frequests" '
        'OR "loadbalancing.googleapis.com%2Frequests")'
    )
    default_window_days = 14
