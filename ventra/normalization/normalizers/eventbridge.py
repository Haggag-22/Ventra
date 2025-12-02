"""
EventBridge resource normalizer.

Normalizes EventBridge rules and buses from collector output.
"""

from typing import Dict, Iterator, Optional, Any, List
from pathlib import Path

from ..core.base import BaseNormalizer
from ..core.context import NormalizationContext
from ..core.schema import Fields, ResourceTypes, RelationshipTypes
from ..core.utils import (
    normalize_timestamp,
    generate_resource_id,
    extract_tags,
    parse_arn,
    extract_account_id_from_arn,
    extract_region_from_arn,
)


class EventBridgeNormalizer(BaseNormalizer):
    """
    Normalizes EventBridge resources from collector JSON files.
    
    Handles:
    - eventbridge_all.json (from eventbridge_all collector)
    """
    
    name = "eventbridge"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load EventBridge data from collector JSON files."""
        # EventBridge files are in resources/ subdirectory
        patterns = [
            "eventbridge_rules*.json",
            "eventbridge_targets*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
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
        """Normalize EventBridge resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "eventbridge_rules*.json",
            "eventbridge_targets*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No EventBridge data found")
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
                # Normalize rules
                rules = data.get("Rules", [])
                for rule_data in rules:
                    rule = self._normalize_rule(rule_data, context)
                    if rule:
                        all_resources.append(rule)
            
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
    
    def _normalize_rule(
        self, rule_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EventBridge rule."""
        rule_name = rule_data.get("Name")
        if not rule_name:
            return None
        
        rule_arn = rule_data.get("Arn")
        account_id = context.account_id
        region = context.region
        
        if rule_arn:
            parsed_arn = parse_arn(rule_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="eventbridge",
            resource_type="rule",
            resource_identifier=rule_name,
            account_id=account_id,
            region=region,
        )
        
        state = rule_data.get("State", "").lower()
        event_bus_name = rule_data.get("EventBusName", "default")
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EVENTBRIDGE_RULE,
            Fields.SERVICE: "eventbridge",
            Fields.RESOURCE_TYPE: "rule",
            Fields.RESOURCE_ID: rule_name,
            Fields.ARN: rule_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: rule_name,
            Fields.STATE: state,
            Fields.STATUS: state,
        }
        
        # Add relationships
        relationships = []
        
        # Extract target ARNs
        targets = rule_data.get("Targets", [])
        for target in targets:
            target_arn = target.get("Arn")
            if target_arn:
                # Determine target type from ARN
                if ":lambda:" in target_arn:
                    relationships.append({
                        "target_arn": target_arn,
                        "target_type": ResourceTypes.LAMBDA_FUNCTION,
                        "relationship_type": RelationshipTypes.USES,
                    })
                elif ":sns:" in target_arn:
                    relationships.append({
                        "target_arn": target_arn,
                        "target_type": ResourceTypes.SNS_TOPIC,
                        "relationship_type": RelationshipTypes.USES,
                    })
                elif ":sqs:" in target_arn:
                    relationships.append({
                        "target_arn": target_arn,
                        "target_type": ResourceTypes.SQS_QUEUE,
                        "relationship_type": RelationshipTypes.USES,
                    })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "description": rule_data.get("Description"),
            "event_bus_name": event_bus_name,
            "schedule_expression": rule_data.get("ScheduleExpression"),
            "event_pattern": rule_data.get("EventPattern"),
            "managed_by": rule_data.get("ManagedBy"),
            "targets_count": len(targets),
        }
        
        return normalized

