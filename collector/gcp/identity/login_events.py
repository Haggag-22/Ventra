"""Login audit events — Google Cloud console and identity sign-ins."""

from ..common.logging_collector import GcpLoggingCollector


class LoginEventsCollector(GcpLoggingCollector):
    name = "login_events"
    priority = 1
    description = "Login audit events (Google Cloud console authentication)."
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'logName:"cloudaudit.googleapis.com%2Fdata_access" '
        'AND protoPayload.methodName=("google.login" OR "google.iam.admin.v1.CreateServiceAccountKey")'
    )
