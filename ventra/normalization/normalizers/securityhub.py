"""
Security Hub resource normalizer.

Normalizes Security Hub findings from collector output.
"""

from typing import Dict, Iterator, Optional, Any, List
from pathlib import Path

from ..core.base import BaseNormalizer
from ..core.context import NormalizationContext
from ..core.schema import Fields, ResourceTypes
from ..core.utils import (
    normalize_timestamp,
    generate_resource_id,
    parse_arn,
    extract_account_id_from_arn,
    extract_region_from_arn,
)


class SecurityHubNormalizer(BaseNormalizer):
    """
    Normalizes Security Hub findings from collector JSON files.
    
    Handles:
    - securityhub_findings.json (from securityhub_findings collector)
    """
    
    name = "securityhub"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load Security Hub data from collector JSON files."""
        # Security Hub and Detective files are in logs/ subdirectory
        patterns = [
            "securityhub_findings.json",
            "detective_findings.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["logs"])
        
        if not files:
            return
        
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            # Skip if Security Hub is not enabled
            if isinstance(data, dict) and data.get("message") == "Security Hub is not enabled":
                continue
            
            yield data
    
    def normalize_record(
        self, raw: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize Security Hub findings."""
        # Handle different file structures
        findings = []
        if isinstance(raw, list):
            findings = raw
        elif "Findings" in raw:
            findings = raw["Findings"]
        elif "findings" in raw:
            findings = raw["findings"]
        elif "Id" in raw:
            findings = [raw]  # Single finding
        
        if not findings:
            return None
        
        # Return None - handled in custom run()
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle findings array."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "securityhub_findings.json",
            "detective_findings.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["logs"])
        
        if not files:
            print(f"    ⚠ No Security Hub data found")
            return NormalizationSummary(
                name=self.name,
                output_path=str(context.output_dir / f"{self.name}.json"),
                record_count=0,
                error_count=0,
            )
        
        all_resources: List[Dict[str, Any]] = []
        errors: List[str] = []
        
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            # Skip if Security Hub is not enabled
            if isinstance(data, dict) and data.get("message") == "Security Hub is not enabled":
                continue
            
            try:
                # Extract findings
                findings = []
                if isinstance(data, list):
                    findings = data
                elif "Findings" in data:
                    findings = data["Findings"]
                elif "findings" in data:
                    findings = data["findings"]
                elif "Id" in data:
                    findings = [data]
                
                for finding_data in findings:
                    finding = self._normalize_finding(finding_data, context)
                    if finding:
                        all_resources.append(finding)
            
            except Exception as e:
                error_msg = f"Error processing {file_path.name}: {str(e)}"
                errors.append(error_msg)
                print(f"    ⚠ {error_msg}")
        
        # Save normalized resources
        output_path = self.save_normalized(context, all_resources)
        
        print(
            f"    ✓ Normalized {len(all_resources)} resource(s) → {output_path.name} "
            f"({len(errors)} error(s))"
        )
        
        return NormalizationSummary(
            name=self.name,
            output_path=str(output_path),
            record_count=len(all_resources),
            error_count=len(errors),
            errors=errors,
        )
    
    def _normalize_finding(
        self, finding_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a Security Hub finding."""
        finding_id = finding_data.get("Id")
        if not finding_id:
            return None
        
        account_id = context.account_id or finding_data.get("AwsAccountId")
        region = context.region or finding_data.get("Region")
        
        resource_id = generate_resource_id(
            service="securityhub",
            resource_type="finding",
            resource_identifier=finding_id,
            account_id=account_id,
            region=region,
        )
        
        created_at = normalize_timestamp(finding_data.get("CreatedAt"))
        updated_at = normalize_timestamp(finding_data.get("UpdatedAt"))
        first_observed = normalize_timestamp(finding_data.get("FirstObservedAt"))
        last_observed = normalize_timestamp(finding_data.get("LastObservedAt"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.SECURITYHUB_FINDING,
            Fields.SERVICE: "securityhub",
            Fields.RESOURCE_TYPE: "finding",
            Fields.RESOURCE_ID: finding_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.CREATED_AT: created_at,
            Fields.UPDATED_AT: updated_at,
            Fields.FIRST_OBSERVED: first_observed,
            Fields.LAST_OBSERVED: last_observed,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "title": finding_data.get("Title"),
            "description": finding_data.get("Description"),
            "severity": finding_data.get("Severity", {}),
            "confidence": finding_data.get("Confidence"),
            "criticality": finding_data.get("Criticality"),
            "types": finding_data.get("Types", []),
            "generator_id": finding_data.get("GeneratorId"),
            "product_arn": finding_data.get("ProductArn"),
            "resources": finding_data.get("Resources", []),
            "remediation": finding_data.get("Remediation", {}),
            "workflow_status": finding_data.get("WorkflowStatus"),
            "record_state": finding_data.get("RecordState"),
            "compliance": finding_data.get("Compliance", {}),
        }
        
        return normalized

