"""Compute Engine VM logs (logging agent / serial port / OS logs)."""

from ..common.logging_collector import GcpLoggingCollector


class VmLogsCollector(GcpLoggingCollector):
    name = "vm_logs"
    priority = 2
    description = "Compute Engine VM logs collected by the Cloud Logging agent."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'resource.type="gce_instance" '
        'AND NOT logName:"compute.googleapis.com%2Fvpc_flows"'
    )
    default_window_days = 14
