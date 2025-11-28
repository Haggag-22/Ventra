"""
Normalization core module.

Provides base classes, schemas, and utilities for normalizing AWS collector data.
"""

from .base import BaseNormalizer, NormalizationError, NormalizationSummary
from .context import NormalizationContext
from .schema import Fields, ResourceTypes, RelationshipTypes, event_schema_template, resource_schema_template, relationship_schema_template
from .utils import (
    parse_arn,
    extract_account_id_from_arn,
    extract_service_from_arn,
    extract_region_from_arn,
    extract_resource_id_from_arn,
    normalize_timestamp,
    normalize_timestamp_field,
    generate_event_id,
    generate_resource_id,
    map_fields,
    extract_tags,
    safe_get_nested,
)

__all__ = [
    # Base classes
    "BaseNormalizer",
    "NormalizationError",
    "NormalizationSummary",
    "NormalizationContext",
    # Schemas
    "Fields",
    "ResourceTypes",
    "RelationshipTypes",
    "event_schema_template",
    "resource_schema_template",
    "relationship_schema_template",
    # Utilities
    "parse_arn",
    "extract_account_id_from_arn",
    "extract_service_from_arn",
    "extract_region_from_arn",
    "extract_resource_id_from_arn",
    "normalize_timestamp",
    "normalize_timestamp_field",
    "generate_event_id",
    "generate_resource_id",
    "map_fields",
    "extract_tags",
    "safe_get_nested",
]

