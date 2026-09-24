"""Azure Activity Log collection constants (Invictus Get-ActivityLogs parity)."""

from __future__ import annotations

from datetime import datetime, timedelta

# Invictus defaults to today -89 days; Azure retains ~90 days.
DEFAULT_WINDOW_DAYS = 89
RETENTION_DAYS = 90
# Query in weekly chunks per subscription to avoid incomplete pages on dense tenants.
CHUNK_DAYS = 7
from collector.lib.limits import DEFAULT_MAX_RECORDS as MAX_RECORDS

RETENTION_NOTE = (
    "Azure Activity Log retains events for approximately 90 days. Ventra defaults to an "
    "89-day lookback (Invictus Get-ActivityLogs parity). Use --since/--until to narrow the window."
)

PERMISSION_NOTE = (
    "Requires Microsoft.Insights/eventtypes/values/read on each in-scope subscription. "
    "Scope collection with --subscription <id> (Invictus -SubscriptionID)."
)
