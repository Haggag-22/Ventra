"""
Utility functions for normalization.

Common helpers for ARN parsing, timestamp normalization, ID generation,
and field mapping used across all normalizers.
"""

import re
from datetime import datetime
from typing import Dict, Optional, Tuple, Union
from urllib.parse import unquote


# =============================================================================
# ARN PARSING
# =============================================================================

def parse_arn(arn: str) -> Optional[Dict[str, str]]:
    """
    Parse an AWS ARN into components.
    
    ARN format: arn:partition:service:region:account-id:resource-type/resource-id
    
    Parameters
    ----------
    arn : str
        AWS Resource Name
    
    Returns
    -------
    dict or None
        Dict with keys: partition, service, region, account_id, resource_type, resource_id
        Returns None if ARN is invalid
    """
    if not arn or not isinstance(arn, str):
        return None
    
    # ARN pattern: arn:partition:service:region:account-id:resource
    pattern = r"^arn:(?P<partition>[^:]+):(?P<service>[^:]+):(?P<region>[^:]*):(?P<account_id>[^:]*):(?P<resource>.+)$"
    match = re.match(pattern, arn)
    
    if not match:
        return None
    
    parts = match.groupdict()
    resource = parts["resource"]
    
    # Split resource into type and ID (e.g., "bucket/my-bucket" or "instance/i-123")
    if "/" in resource:
        resource_type, resource_id = resource.split("/", 1)
    else:
        resource_type = ""
        resource_id = resource
    
    return {
        "partition": parts["partition"],
        "service": parts["service"],
        "region": parts["region"] or None,
        "account_id": parts["account_id"] or None,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "full_resource": resource,
    }


def extract_account_id_from_arn(arn: str) -> Optional[str]:
    """Extract account ID from ARN."""
    parsed = parse_arn(arn)
    return parsed.get("account_id") if parsed else None


def extract_service_from_arn(arn: str) -> Optional[str]:
    """Extract service name from ARN."""
    parsed = parse_arn(arn)
    return parsed.get("service") if parsed else None


def extract_region_from_arn(arn: str) -> Optional[str]:
    """Extract region from ARN."""
    parsed = parse_arn(arn)
    return parsed.get("region") if parsed else None


def extract_resource_id_from_arn(arn: str) -> Optional[str]:
    """Extract resource ID from ARN."""
    parsed = parse_arn(arn)
    return parsed.get("resource_id") if parsed else None


# =============================================================================
# TIMESTAMP NORMALIZATION
# =============================================================================

def normalize_timestamp(
    value: Optional[Union[str, datetime, int, float]],
    default: Optional[str] = None,
) -> Optional[str]:
    """
    Normalize timestamp to ISO 8601 UTC string.
    
    Handles various input formats:
    - ISO 8601 strings (with or without timezone)
    - datetime objects
    - Unix timestamps (int/float)
    - None/empty values
    
    Parameters
    ----------
    value : str, datetime, int, float, or None
        Timestamp value to normalize
    default : str, optional
        Default value if normalization fails
    
    Returns
    -------
    str or None
        ISO 8601 UTC timestamp string (e.g., "2024-01-15T10:30:00Z")
    """
    if value is None:
        return default
    
    # Already a string
    if isinstance(value, str):
        value = value.strip()
        if not value or value.lower() in ("none", "null", ""):
            return default
        
        # Try parsing ISO 8601
        try:
            # Handle various ISO formats
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                # Assume UTC if no timezone
                dt = dt.replace(tzinfo=datetime.utcnow().tzinfo)
            return dt.astimezone(datetime.utcnow().tzinfo).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, AttributeError):
            # Try parsing as Unix timestamp string
            try:
                ts = float(value)
                dt = datetime.utcfromtimestamp(ts)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OSError):
                return default
    
    # datetime object
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.utcnow().tzinfo)
        return value.astimezone(datetime.utcnow().tzinfo).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Unix timestamp (int or float)
    if isinstance(value, (int, float)):
        try:
            dt = datetime.utcfromtimestamp(value)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, ValueError):
            return default
    
    return default


def normalize_timestamp_field(
    data: Dict[str, any],
    source_field: str,
    target_field: Optional[str] = None,
    default: Optional[str] = None,
) -> Optional[str]:
    """
    Extract and normalize a timestamp field from a dict.
    
    Parameters
    ----------
    data : dict
        Source dictionary
    source_field : str
        Field name in source dict
    target_field : str, optional
        If provided, also set this field in the dict
    default : str, optional
        Default value if field is missing/invalid
    
    Returns
    -------
    str or None
        Normalized timestamp
    """
    value = data.get(source_field)
    normalized = normalize_timestamp(value, default=default)
    
    if target_field and normalized:
        data[target_field] = normalized
    
    return normalized


# =============================================================================
# ID GENERATION
# =============================================================================

def generate_event_id(
    event_name: str,
    event_time: str,
    request_id: Optional[str] = None,
    account_id: Optional[str] = None,
) -> str:
    """
    Generate a unique event ID.
    
    Format: {account_id}:{event_time}:{event_name}:{request_id_hash}
    
    Parameters
    ----------
    event_name : str
        Event name (e.g., "CreateBucket")
    event_time : str
        ISO 8601 timestamp
    request_id : str, optional
        AWS request ID
    account_id : str, optional
        AWS account ID
    
    Returns
    -------
    str
        Unique event ID
    """
    import hashlib
    
    parts = []
    if account_id:
        parts.append(account_id)
    
    # Normalize timestamp for ID (remove colons and special chars)
    time_part = event_time.replace(":", "").replace("-", "").replace("T", "").replace("Z", "")
    parts.append(time_part[:14])  # YYYYMMDDHHMMSS
    
    parts.append(event_name)
    
    if request_id:
        # Hash request ID to keep ID reasonable length
        req_hash = hashlib.md5(request_id.encode()).hexdigest()[:8]
        parts.append(req_hash)
    
    return ":".join(parts)


def generate_resource_id(
    service: str,
    resource_type: str,
    resource_identifier: str,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """
    Generate a unique resource ID.
    
    Format: {service}:{resource_type}:{account_id}:{region}:{identifier}
    
    Parameters
    ----------
    service : str
        AWS service (e.g., "s3", "ec2")
    resource_type : str
        Resource type (e.g., "bucket", "instance")
    resource_identifier : str
        Service-specific identifier (e.g., bucket name, instance-id)
    account_id : str, optional
        AWS account ID
    region : str, optional
        AWS region
    
    Returns
    -------
    str
        Unique resource ID
    """
    parts = [service, resource_type]
    
    if account_id:
        parts.append(account_id)
    else:
        parts.append("")
    
    if region:
        parts.append(region)
    else:
        parts.append("")
    
    parts.append(resource_identifier)
    
    return ":".join(parts)


# =============================================================================
# FIELD MAPPING HELPERS
# =============================================================================

def map_fields(
    source: Dict[str, any],
    field_mapping: Dict[str, Union[str, Tuple[str, callable]]],
    default_values: Optional[Dict[str, any]] = None,
) -> Dict[str, any]:
    """
    Map fields from source dict to target dict using a mapping.
    
    Parameters
    ----------
    source : dict
        Source dictionary
    field_mapping : dict
        Mapping of target_field -> source_field or (source_field, transform_func)
        Example: {"name": "BucketName", "size": ("Size", int)}
    default_values : dict, optional
        Default values for missing fields
    
    Returns
    -------
    dict
        Mapped dictionary
    """
    result = {}
    
    if default_values:
        result.update(default_values)
    
    for target_field, mapping in field_mapping.items():
        if isinstance(mapping, tuple):
            source_field, transform_func = mapping
            value = source.get(source_field)
            if value is not None:
                try:
                    result[target_field] = transform_func(value)
                except Exception:
                    pass  # Skip if transform fails
        else:
            # Simple field copy
            source_field = mapping
            value = source.get(source_field)
            if value is not None:
                result[target_field] = value
    
    return result


def extract_tags(tags_list: Optional[list]) -> Dict[str, str]:
    """
    Extract tags from AWS tag format to simple dict.
    
    AWS tags are typically: [{"Key": "Name", "Value": "MyResource"}, ...]
    
    Parameters
    ----------
    tags_list : list of dict, optional
        List of tag dicts with Key/Value
    
    Returns
    -------
    dict
        Simple dict mapping tag keys to values
    """
    if not tags_list:
        return {}
    
    result = {}
    for tag in tags_list:
        if isinstance(tag, dict):
            key = tag.get("Key") or tag.get("key")
            value = tag.get("Value") or tag.get("value")
            if key:
                result[key] = value or ""
    
    return result


def safe_get_nested(data: Dict, *keys, default=None):
    """
    Safely get nested dict value.
    
    Example: safe_get_nested(data, "BucketInfo", "encryption", "Rules", default=[])
    
    Parameters
    ----------
    data : dict
        Source dictionary
    *keys : str
        Nested keys to traverse
    default : any
        Default value if path doesn't exist
    
    Returns
    -------
    any
        Value at path or default
    """
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return default
        else:
            return default
    return current if current is not None else default

