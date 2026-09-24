"""Configurable collection limits for enterprise vs triage profiles."""

from __future__ import annotations

# Paginator ceiling for full-window collection (since/until). Optional triage caps use a
# positive max_records_per_source in acquisition.yaml instead.
UNLIMITED_RECORDS = 1_000_000_000
UNLIMITED_OBJECTS = 1_000_000_000

# Legacy alias — collectors import this as a per-source fallback constant; effective caps come
# from Collector.max_records() which defaults to unlimited when acquisition.yaml omits a cap.
DEFAULT_MAX_RECORDS = UNLIMITED_RECORDS
DEFAULT_MAX_LOG_OBJECTS = UNLIMITED_OBJECTS


def records_unlimited(max_records: int) -> bool:
    return max_records >= UNLIMITED_RECORDS // 2


def resolve_max_objects(max_records: int, max_objects: int | None = None) -> int:
    if max_objects is not None:
        return max_objects
    return UNLIMITED_OBJECTS if records_unlimited(max_records) else DEFAULT_MAX_LOG_OBJECTS
