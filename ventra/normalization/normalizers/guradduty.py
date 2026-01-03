"""
GuardDuty resource normalizer.

Normalizes GuardDuty detectors and findings from collector output.
"""

from typing import Dict, Iterator, Optional, Any, List
from pathlib import Path

from ..core.base import BaseNormalizer
from ..core.context import NormalizationContext
from ..core.schema import Fields, ResourceTypes
from ..core.utils import (
    normalize_timestamp,
    generate_resource_id,
    extract_tags,
    parse_arn,
    extract_account_id_from_arn,
    extract_region_from_arn,
)


class GuardDutyNormalizer(BaseNormalizer):
    """
    Normalizes GuardDuty resources from collector JSON files.
    
    Handles:
    - guradduty_all.json (from guradduty_all collector)
    - guradduty_findings.json
    """
    
    name = "guradduty"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load GuardDuty data from collector JSON files."""
        patterns = ["guradduty_all.json", "guradduty_findings.json"]
        files = self.find_collector_files(context, patterns)
        
        if not files:
            return
        
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            yield data
    
    def normalize_record(
        self, raw: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize GuardDuty resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = ["guradduty_all.json", "guradduty_findings.json"]
        files = self.find_collector_files(context, patterns)
        
        if not files:
            print(f"    ⚠ No GuardDuty data found")
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
            
            try:
                # Handle detectors structure
                detectors = data.get("Detectors", [])
                for detector_data in detectors:
                    detector_id = detector_data.get("DetectorId")
                    detector_details = detector_data.get("DetectorDetails", {})
                    
                    # Normalize detector
                    detector = self._normalize_detector(detector_id, detector_details, context)
                    if detector:
                        all_resources.append(detector)
                    
                    # Normalize findings
                    findings = detector_data.get("Findings", [])
                    for finding_data in findings:
                        finding = self._normalize_finding(finding_data, detector_id, context)
                        if finding:
                            all_resources.append(finding)
                
                # Handle standalone findings file
                if "Findings" in data and not detectors:
                    findings = data.get("Findings", [])
                    for finding_data in findings:
                        finding = self._normalize_finding(finding_data, None, context)
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
    
    def _normalize_detector(
        self, detector_id: str, detector_details: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a GuardDuty detector."""
        if not detector_id:
            return None
        
        account_id = context.account_id
        region = context.region
        
        resource_id = generate_resource_id(
            service="guardduty",
            resource_type="detector",
            resource_identifier=detector_id,
            account_id=account_id,
            region=region,
        )
        
        created_at = normalize_timestamp(detector_details.get("CreatedAt"))
        updated_at = normalize_timestamp(detector_details.get("UpdatedAt"))
        status = detector_details.get("Status", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.GUARDDUTY_DETECTOR,
            Fields.SERVICE: "guardduty",
            Fields.RESOURCE_TYPE: "detector",
            Fields.RESOURCE_ID: detector_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: detector_id,
            Fields.STATUS: status,
            Fields.STATE: status,
            Fields.CREATED_AT: created_at,
            Fields.UPDATED_AT: updated_at,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "finding_publishing_frequency": detector_details.get("FindingPublishingFrequency"),
            "data_sources": detector_details.get("DataSources", {}),
            "service_role": detector_details.get("ServiceRole"),
        }
        
        return normalized
    
    def _normalize_finding(
        self, finding_data: Dict[str, Any], detector_id: Optional[str], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a GuardDuty finding."""
        finding_id = finding_data.get("Id")
        if not finding_id:
            return None
        
        finding_arn = finding_data.get("Arn")
        account_id = context.account_id or finding_data.get("AccountId")
        region = context.region or finding_data.get("Region")
        
        if finding_arn:
            parsed_arn = parse_arn(finding_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="guardduty",
            resource_type="finding",
            resource_identifier=finding_id,
            account_id=account_id,
            region=region,
        )
        
        created_at = normalize_timestamp(finding_data.get("CreatedAt"))
        updated_at = normalize_timestamp(finding_data.get("UpdatedAt"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.GUARDDUTY_FINDING,
            Fields.SERVICE: "guardduty",
            Fields.RESOURCE_TYPE: "finding",
            Fields.RESOURCE_ID: finding_id,
            Fields.ARN: finding_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.CREATED_AT: created_at,
            Fields.UPDATED_AT: updated_at,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "detector_id": detector_id,
            "title": finding_data.get("Title"),
            "description": finding_data.get("Description"),
            "severity": finding_data.get("Severity"),
            "type": finding_data.get("Type"),
            "resource": finding_data.get("Resource", {}),
            "service": finding_data.get("Service", {}),
        }
        
        return normalized

