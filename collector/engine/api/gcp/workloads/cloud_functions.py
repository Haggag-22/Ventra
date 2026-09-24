"""Cloud Functions execution logs."""

from ..common.logging_collector import GcpLoggingCollector


class CloudFunctionsCollector(GcpLoggingCollector):
    name = "cloud_functions"
    priority = 2
    description = "Cloud Functions execution and platform logs."
    required_actions = ("logging.logEntries.list",)
    log_filter = 'logName:"cloudfunctions.googleapis.com%2Fcloud-functions"'
    default_window_days = 14
