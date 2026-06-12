"""Additive enrichment of normalized events. Never modifies ``raw``.

Enrichment is intentionally dependency-light and offline-first: it ships with a small private
IP / known-cloud classifier and optional GeoIP/ASN if a local database is provided. IOC
matching runs against a per-case list supplied by the analyst.
"""

from .enrich import enrich_events, Enricher

__all__ = ["enrich_events", "Enricher"]
