"""
Event-to-Resource Correlator.

Links events to resources they affect, create, modify, or access.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from ..core.base import BaseCorrelator, CorrelationSummary
from ..core.context import CorrelationContext
from ..core.schema import CorrelationFields, RelationshipTypes


class EventToResourceCorrelator(BaseCorrelator):
    """Correlates events to resources."""
    
    name = "event_to_resource"
    
    def correlate(self, context: CorrelationContext) -> CorrelationSummary:
        """Correlate events to resources."""
        # Load all normalized files
        all_files = list(context.normalized_dir.glob("*.json"))
        
        events = []
        resources = {}
        
        for file_path in all_files:
            data = self.load_normalized_file(file_path)
            if not data:
                continue
            
            records = data.get("records", [])
            for record in records:
                record_type = record.get("type", "")
                
                # Separate events and resources
                if record_type.startswith("aws.cloudtrail.event") or \
                   record_type.startswith("aws.cloudwatch.log_event"):
                    events.append(record)
                else:
                    # It's a resource
                    resource_id = record.get("id") or record.get("resource_id")
                    if resource_id:
                        resources[resource_id] = record
                        # Also index by ARN
                        arn = record.get("arn")
                        if arn:
                            resources[arn] = record
                        # Also index by resource_id field
                        rid = record.get("resource_id")
                        if rid:
                            resources[rid] = record
        
        if not events or not resources:
            return CorrelationSummary(
                name=self.name,
                output_path=str(context.output_dir / "event_resource_correlations.json"),
                records_processed=len(events),
                correlations_found=0,
            )
        
        # Correlate events to resources
        correlations_found = 0
        errors = []
        
        for event in events:
            if "correlations" not in event:
                event["correlations"] = {}
            
            related_resources = []
            
            # Match by ARN
            event_arn = event.get("arn")
            if event_arn and event_arn in resources:
                related_resources.append({
                    "resource_id": resources[event_arn].get("id"),
                    "resource_type": resources[event_arn].get("type"),
                    "relationship": RelationshipTypes.AFFECTS_RESOURCE,
                    CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.95,
                    CorrelationFields.RELATIONSHIP_EVIDENCE: f"ARN match: {event_arn}",
                })
            
            # Match by resource_id
            event_resource_id = event.get("resource_id")
            if event_resource_id:
                # Try direct match
                if event_resource_id in resources:
                    related_resources.append({
                        "resource_id": resources[event_resource_id].get("id"),
                        "resource_type": resources[event_resource_id].get("type"),
                        "relationship": RelationshipTypes.AFFECTS_RESOURCE,
                        CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.9,
                        CorrelationFields.RELATIONSHIP_EVIDENCE: f"Resource ID match: {event_resource_id}",
                    })
                
                # Try service-based matching
                event_service = event.get("service")
                if event_service:
                    # Look for resources in the same service
                    for resource_id, resource in resources.items():
                        if isinstance(resource, dict) and resource.get("service") == event_service:
                            # Check if resource_id matches
                            if event_resource_id in str(resource.get("resource_id", "")) or \
                               event_resource_id in str(resource.get("id", "")):
                                related_resources.append({
                                    "resource_id": resource.get("id"),
                                    "resource_type": resource.get("type"),
                                    "relationship": RelationshipTypes.AFFECTS_RESOURCE,
                                    CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.7,
                                    CorrelationFields.RELATIONSHIP_EVIDENCE: f"Service match: {event_service}",
                                })
                                break
            
            # Match by event name patterns (e.g., CreateBucket -> s3 bucket)
            event_name = event.get("event_name", "")
            if event_name:
                # Pattern: CreateX -> X resource
                if event_name.startswith("Create"):
                    resource_type = event_name.replace("Create", "").lower()
                    # Try to find matching resource
                    for resource_id, resource in resources.items():
                        if isinstance(resource, dict):
                            res_type = resource.get("resource_type", "").lower()
                            if resource_type in res_type or res_type in resource_type:
                                related_resources.append({
                                    "resource_id": resource.get("id"),
                                    "resource_type": resource.get("type"),
                                    "relationship": RelationshipTypes.CREATED_RESOURCE,
                                    CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.6,
                                    CorrelationFields.RELATIONSHIP_EVIDENCE: f"Event name pattern: {event_name}",
                                })
                                break
            
            # Remove duplicates
            seen = set()
            unique_related = []
            for rel in related_resources:
                key = rel.get("resource_id")
                if key and key not in seen:
                    seen.add(key)
                    unique_related.append(rel)
            
            if unique_related:
                event["correlations"][CorrelationFields.RELATED_RESOURCES] = unique_related[:20]  # Limit to 20
                correlations_found += len(unique_related)
        
        # Save correlated data
        output_data = {
            "correlator": self.name,
            "correlated_at": datetime.utcnow().isoformat() + "Z",
            "total_events": len(events),
            "total_resources": len(resources),
            "correlations_found": correlations_found,
            "events": events[:1000],  # Limit for now
        }
        
        output_path = self.save_correlated_file(context, output_data, "event_resource_correlations.json")
        
        return CorrelationSummary(
            name=self.name,
            output_path=str(output_path),
            records_processed=len(events),
            correlations_found=correlations_found,
            error_count=len(errors),
            errors=errors,
        )

