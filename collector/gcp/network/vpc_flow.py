"""VPC Flow Logs."""

from ..common.logging_collector import GcpLoggingCollector


class VpcFlowCollector(GcpLoggingCollector):
    name = "vpc_flow"
    priority = 1
    description = "VPC Flow Logs (sampled L3/L4 traffic within VPCs)."
    required_actions = ("logging.logEntries.list", "compute.subnetworks.list")
    log_filter = 'logName:"compute.googleapis.com%2Fvpc_flows"'
    default_window_days = 14
