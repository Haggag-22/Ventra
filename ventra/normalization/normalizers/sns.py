"""
SNS resource normalizer.

Normalizes SNS topics and subscriptions from collector output.
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


class SNSNormalizer(BaseNormalizer):
    """
    Normalizes SNS resources from collector JSON files.
    
    Handles:
    - sns_all.json (from sns_all collector)
    """
    
    name = "sns"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load SNS data from collector JSON files."""
        # SNS files are in resources/ subdirectory
        patterns = ["sns*.json"]  # Will match any SNS collector output
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
        """Normalize SNS resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = ["sns*.json"]  # Will match any SNS collector output
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No SNS data found")
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
                # Normalize topics
                topics = data.get("Topics", [])
                for topic_data in topics:
                    topic = self._normalize_topic(topic_data, context)
                    if topic:
                        all_resources.append(topic)
            
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
    
    def _normalize_topic(
        self, topic_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an SNS topic."""
        topic_arn = topic_data.get("TopicArn")
        if not topic_arn:
            return None
        
        parsed_arn = parse_arn(topic_arn)
        account_id = context.account_id
        region = context.region
        
        if parsed_arn:
            account_id = parsed_arn.get("account_id") or account_id
            region = parsed_arn.get("region") or region
        
        # Extract topic name from ARN
        topic_name = topic_arn.split(":")[-1]
        
        resource_id = generate_resource_id(
            service="sns",
            resource_type="topic",
            resource_identifier=topic_name,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(topic_data.get("Tags", {}))
        attributes = topic_data.get("Attributes", {})
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.SNS_TOPIC,
            Fields.SERVICE: "sns",
            Fields.RESOURCE_TYPE: "topic",
            Fields.RESOURCE_ID: topic_name,
            Fields.ARN: topic_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: topic_name,
            Fields.TAGS: tags,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "display_name": attributes.get("DisplayName"),
            "subscriptions_confirmed": int(attributes.get("SubscriptionsConfirmed", 0)),
            "subscriptions_pending": int(attributes.get("SubscriptionsPending", 0)),
            "subscriptions_deleted": int(attributes.get("SubscriptionsDeleted", 0)),
            "policy": attributes.get("Policy"),
            "effective_delivery_policy": attributes.get("EffectiveDeliveryPolicy"),
        }
        
        return normalized

