"""Login audit events — Google Cloud console and identity sign-ins."""

from ..common.logging_collector import GcpLoggingCollector


class LoginEventsCollector(GcpLoggingCollector):
    name = "login_events"
    priority = 1
    description = "Login audit events (Google Cloud console authentication)."
    required_actions = ("logging.logEntries.list",)
    # Sign-in audit events are the login.googleapis.com serviceName view over the shared
    # data_access stream (a filter over that table, not a separate log).
    log_filter = (
        'logName:"cloudaudit.googleapis.com%2Fdata_access" '
        'AND protoPayload.serviceName="login.googleapis.com"'
    )
