"""Cloud Load Balancer access logs."""

from ..common.logging_collector import GcpLoggingCollector


class LoadBalancerCollector(GcpLoggingCollector):
    name = "load_balancer"
    priority = 1
    description = "Load Balancer Access Logs for HTTP(S) and TCP/UDP proxy load balancers."
    required_actions = ("logging.logEntries.list",)
    # The LB request log is named bare `requests` on modern sinks (older sinks used
    # compute.googleapis.com/requests) — resource.type is the reliable discriminator.
    log_filter = 'resource.type="http_load_balancer" AND logName:"requests"'
    default_window_days = 14
