"""
Resource-to-Resource Correlator.

Links resources together based on relationships defined in normalized data.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from ..core.base import BaseCorrelator, CorrelationSummary
from ..core.context import CorrelationContext
from ..core.schema import CorrelationFields


class ResourceToResourceCorrelator(BaseCorrelator):
    """Correlates resources to other resources."""
    
    name = "resource_to_resource"
    
    def correlate(self, context: CorrelationContext) -> CorrelationSummary:
        """Correlate resources to other resources."""
        # Load all normalized files
        all_files = list(context.normalized_dir.glob("*.json"))
        
        resources = {}
        
        for file_path in all_files:
            data = self.load_normalized_file(file_path)
            if not data:
                continue
            
            records = data.get("records", [])
            for record in records:
                record_type = record.get("type", "")
                
                # Only process resources (not events)
                if not record_type.startswith("aws.cloudtrail.event") and \
                   not record_type.startswith("aws.cloudwatch.log_event"):
                    resource_id = record.get("id")
                    if resource_id:
                        resources[resource_id] = record
        
        if len(resources) < 2:
            return CorrelationSummary(
                name=self.name,
                output_path=str(context.output_dir / "resource_correlations.json"),
                records_processed=len(resources),
                correlations_found=0,
            )
        
        # Process existing relationships from normalized data
        correlations_found = 0
        errors = []
        
        for resource_id, resource in resources.items():
            if "correlations" not in resource:
                resource["correlations"] = {}
            
            # Extract relationships from normalized data
            relationships = resource.get("relationships", [])
            if relationships:
                related_resources = []
                
                for rel in relationships:
                    target_id = rel.get("target_id") or rel.get("target_arn")
                    if target_id and target_id in resources:
                        related_resources.append({
                            "resource_id": target_id,
                            "resource_type": rel.get("target_type"),
                            "relationship": rel.get("relationship_type"),
                            CorrelationFields.RELATIONSHIP_CONFIDENCE: 1.0,  # From normalized data
                            CorrelationFields.RELATIONSHIP_EVIDENCE: "From normalized relationships",
                        })
                
                if related_resources:
                    resource["correlations"][CorrelationFields.RELATED_RESOURCES] = related_resources
                    correlations_found += len(related_resources)
        
        # Save correlated resources
        output_data = {
            "correlator": self.name,
            "correlated_at": datetime.utcnow().isoformat() + "Z",
            "total_resources": len(resources),
            "correlations_found": correlations_found,
            "resources": list(resources.values())[:1000],  # Limit for now
        }
        
        output_path = self.save_correlated_file(context, output_data, "resource_correlations.json")
        
        return CorrelationSummary(
            name=self.name,
            output_path=str(output_path),
            records_processed=len(resources),
            correlations_found=correlations_found,
            error_count=len(errors),
            errors=errors,
        )

