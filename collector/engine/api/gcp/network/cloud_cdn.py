"""Cloud CDN cache request logs."""

from ..common.logging_collector import GcpLoggingCollector


class CloudCdnCollector(GcpLoggingCollector):
    name = "cloud_cdn"
    priority = 2
    description = (
        "Cloud CDN cache hit/miss, cache fill, and byte-range request logs from "
        "HTTP(S) load balancer access logging."
    )
    required_actions = ("logging.logEntries.list",)
    log_filter = (
        'resource.type="http_load_balancer" AND ('
        "httpRequest.cacheLookup=true OR jsonPayload.cacheLookup=true"
        ")"
    )
    default_window_days = 14
