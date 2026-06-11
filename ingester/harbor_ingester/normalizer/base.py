"""Unified event model + the source-normalizer registry.

A ``UnifiedEvent`` is the ECS-aligned shape every event source maps to (see
``schemas/unified-event.schema.json``). It is stored flattened in Parquet so the console can
query columns directly with DuckDB; the original record is preserved under ``raw``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterator


@dataclass
class UnifiedEvent:
    timestamp: str  # @timestamp, RFC 3339 UTC
    event_kind: str = "event"  # alert | event | state | finding
    event_category: list[str] = field(default_factory=list)
    event_action: str = ""
    event_outcome: str = "unknown"  # success | failure | unknown
    event_severity: str = "info"  # critical | high | medium | low | info
    event_provider: str = ""

    cloud_provider: str = "aws"
    cloud_account: str = ""
    cloud_region: str = ""
    cloud_service: str = ""

    user_name: str = ""
    user_id: str = ""
    user_arn: str = ""
    user_type: str = ""

    source_ip: str = ""
    source_country: str = ""
    source_asn: str = ""

    dest_ip: str = ""
    dest_port: int | None = None
    dest_bytes: int | None = None

    resource_type: str = ""
    resource_id: str = ""
    resource_arn: str = ""

    ua_original: str = ""
    ua_category: str = ""

    related_ip: list[str] = field(default_factory=list)
    related_user: list[str] = field(default_factory=list)
    related_resource: list[str] = field(default_factory=list)

    message: str = ""

    # Harbor bookkeeping
    case_id: str = ""
    harbor_source: str = ""
    parser_version: str = "1.0.0"

    raw: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        """Flatten for Parquet: list/dict columns become JSON strings."""
        d = asdict(self)
        d["event_category"] = json.dumps(self.event_category)
        d["related_ip"] = json.dumps(sorted(set(self.related_ip)))
        d["related_user"] = json.dumps(sorted(set(self.related_user)))
        d["related_resource"] = json.dumps(sorted(set(self.related_resource)))
        d["raw"] = json.dumps(self.raw, default=str)
        return d


# source name -> generator(records, context) -> UnifiedEvent
SourceNormalizer = Callable[[Any, "NormalizeContext"], Iterator[UnifiedEvent]]
SOURCE_NORMALIZERS: dict[str, SourceNormalizer] = {}


def register(source: str) -> Callable[[SourceNormalizer], SourceNormalizer]:
    def deco(fn: SourceNormalizer) -> SourceNormalizer:
        SOURCE_NORMALIZERS[source] = fn
        return fn

    return deco


@dataclass
class NormalizeContext:
    case_id: str
    account_id: str


def normalize_source(
    source: str, records: list[dict], ctx: NormalizeContext
) -> Iterator[UnifiedEvent]:
    fn = SOURCE_NORMALIZERS.get(source)
    if fn is None:
        return iter(())
    return fn(records, ctx)


def has_normalizer(source: str) -> bool:
    return source in SOURCE_NORMALIZERS
