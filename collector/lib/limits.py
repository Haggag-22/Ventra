"""Configurable collection limits for enterprise vs triage profiles."""

from __future__ import annotations

# Triage default when acquisition.yaml omits max_records_per_source.
DEFAULT_MAX_RECORDS = 200_000

# Paginator ceiling when max_records_per_source is 0 or negative (unlimited within window).
UNLIMITED_RECORDS = 1_000_000_000

# S3 object scan cap for triage; unlimited runs use UNLIMITED_OBJECTS.
DEFAULT_MAX_LOG_OBJECTS = 2000
UNLIMITED_OBJECTS = 1_000_000_000


def records_unlimited(max_records: int) -> bool:
    return max_records >= UNLIMITED_RECORDS // 2


def resolve_max_objects(max_records: int, max_objects: int | None = None) -> int:
    if max_objects is not None:
        return max_objects
    return UNLIMITED_OBJECTS if records_unlimited(max_records) else DEFAULT_MAX_LOG_OBJECTS
