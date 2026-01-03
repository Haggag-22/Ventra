"""
CloudTrail event normalizer.

Normalizes CloudTrail events from collector output into standardized event schema.
"""

from typing import Dict, Iterator, Optional, Any
from pathlib import Path

from ..core.base import BaseNormalizer
from ..core.context import NormalizationContext
from ..core.schema import Fields, ResourceTypes
from ..core.utils import (
    normalize_timestamp,
    generate_event_id,
    extract_account_id_from_arn,
    extract_service_from_arn,
    extract_region_from_arn,
    safe_get_nested,
)


class CloudTrailNormalizer(BaseNormalizer):
    """
    Normalizes CloudTrail events from collector JSON files.
    
    Handles:
    - cloudtrail_history_raw.json (from LookupEvents API)
    - cloudtrail_s3_*.json (from S3 bucket logs)
    """
    
    name = "cloudtrail"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load CloudTrail events from collector JSON files."""
        # Find CloudTrail collector files in logs/ subdirectory
        patterns = [
            "cloudtrail_history_raw.json",
            "cloudtrail_s3_*.json",
            "cloudtrail_lake_*.json",
            "s3_*cloudtrail*.json",  # S3 bucket files that might contain CloudTrail logs
        ]
        
        files = self.find_collector_files(context, patterns, subdirs=["logs"])
        
        if not files:
            return
        
        # Load and yield events from each file
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            # Handle different file structures
            if isinstance(data, list):
                # Direct list of events
                for event in data:
                    yield event
            elif isinstance(data, dict):
                # May have nested structure (e.g., {"events": [...]})
                if "Records" in data:
                    # CloudTrail log format
                    for event in data["Records"]:
                        yield event
                elif "events" in data:
                    for event in data["events"]:
                        yield event
                elif "results" in data:
                    # CloudTrail Lake format
                    for event in data["results"]:
                        yield event
                else:
                    # Single event dict
                    yield data
    
    def normalize_record(
        self, raw: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """
        Normalize a single CloudTrail event.
        
        CloudTrail event structure:
        - eventTime
        - eventName
        - eventSource
        - userIdentity
        - sourceIPAddress
        - userAgent
        - requestID
        - errorCode/errorMessage
        - resources
        - awsRegion
        - recipientAccountId
        """
        # Extract core fields
        event_time = normalize_timestamp(raw.get("eventTime"))
        if not event_time:
            # Skip events without valid timestamps
            return None
        
        event_name = raw.get("eventName", "")
        event_source = raw.get("eventSource", "")
        
        # Extract account ID (prefer recipientAccountId, fallback to context)
        account_id = raw.get("recipientAccountId") or context.account_id
        
        # Extract region (prefer awsRegion, fallback to context)
        region = raw.get("awsRegion") or context.region
        
        # Extract service from eventSource (e.g., "s3.amazonaws.com" -> "s3")
        service = None
        if event_source:
            # Try extracting from ARN format first
            service = extract_service_from_arn(event_source)
            if not service and "." in event_source:
                # Parse service from eventSource domain
                service = event_source.split(".")[0]
        
        # Generate event ID
        request_id = raw.get("requestID") or raw.get("requestId")
        event_id = generate_event_id(
            event_name=event_name,
            event_time=event_time,
            request_id=request_id,
            account_id=account_id,
        )
        
        # Extract user identity
        user_identity = raw.get("userIdentity", {})
        
        # Extract resources
        resources = raw.get("resources", [])
        resource_id = None
        resource_arn = None
        if resources:
            # Use first resource as primary
            first_resource = resources[0]
            resource_id = first_resource.get("resourceName")
            resource_arn = first_resource.get("resourceARN")
        
        # Build normalized event
        normalized = {
            Fields.EVENT_ID: event_id,
            Fields.TYPE: ResourceTypes.CLOUDTRAIL_EVENT,
            Fields.SERVICE: service or "cloudtrail",
            Fields.EVENT_TIME: event_time,
            Fields.EVENT_NAME: event_name,
            Fields.EVENT_SOURCE: event_source,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.USER_IDENTITY: user_identity,
            Fields.SOURCE_IP: raw.get("sourceIPAddress"),
            Fields.USER_AGENT: raw.get("userAgent"),
            Fields.REQUEST_ID: request_id,
            Fields.ERROR_CODE: raw.get("errorCode"),
            Fields.ERROR_MESSAGE: raw.get("errorMessage"),
            Fields.RESOURCE_ID: resource_id,
            Fields.ARN: resource_arn,
        }
        
        # Add resources array if present
        if resources:
            normalized["resources"] = resources
        
        # Optionally preserve raw data
        if context.extras.get("preserve_raw", False):
            normalized[Fields.RAW] = raw
        
        return normalized

