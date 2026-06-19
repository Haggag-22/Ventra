"""API Gateway request logs."""

from ..common.logging_collector import GcpLoggingCollector


class ApiGatewayCollector(GcpLoggingCollector):
    name = "api_gateway"
    priority = 2
    description = "API Gateway request and gateway logs."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"apigateway.googleapis.com%2Fgateway"'
    default_window_days = 14
