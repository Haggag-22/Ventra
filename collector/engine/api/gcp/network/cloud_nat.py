"""Cloud NAT gateway flow logs."""

from ..common.logging_collector import GcpLoggingCollector


class CloudNatCollector(GcpLoggingCollector):
    name = "cloud_nat"
    priority = 1
    description = "Cloud NAT gateway translation logs from Cloud Logging."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'resource.type="nat_gateway" AND logName:"compute.googleapis.com%2Fnat_flows"'
    )
    default_window_days = 14
