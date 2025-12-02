"""
SQS resource normalizer.

Normalizes SQS queues from collector output.
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


class SQSNormalizer(BaseNormalizer):
    """
    Normalizes SQS queues from collector JSON files.
    
    Handles:
    - sqs_all.json (from sqs_all collector)
    """
    
    name = "sqs"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load SQS data from collector JSON files."""
        # SQS files are in resources/ subdirectory
        patterns = ["sqs*.json"]  # Will match any SQS collector output
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
        """Normalize SQS resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = ["sqs*.json"]  # Will match any SQS collector output
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No SQS data found")
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
                # Normalize queues
                queues = data.get("Queues", [])
                for queue_data in queues:
                    queue = self._normalize_queue(queue_data, context)
                    if queue:
                        all_resources.append(queue)
            
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
    
    def _normalize_queue(
        self, queue_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an SQS queue."""
        queue_name = queue_data.get("QueueName")
        if not queue_name:
            return None
        
        attributes = queue_data.get("Attributes", {})
        queue_arn = attributes.get("QueueArn")
        
        account_id = context.account_id
        region = context.region
        
        if queue_arn:
            parsed_arn = parse_arn(queue_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="sqs",
            resource_type="queue",
            resource_identifier=queue_name,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(queue_data.get("Tags", {}))
        created_timestamp = normalize_timestamp(attributes.get("CreatedTimestamp"))
        last_modified = normalize_timestamp(attributes.get("LastModifiedTimestamp"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.SQS_QUEUE,
            Fields.SERVICE: "sqs",
            Fields.RESOURCE_TYPE: "queue",
            Fields.RESOURCE_ID: queue_name,
            Fields.ARN: queue_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: queue_name,
            Fields.CREATED_AT: created_timestamp,
            Fields.LAST_MODIFIED: last_modified,
            Fields.TAGS: tags,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "queue_url": queue_data.get("QueueUrl"),
            "approximate_number_of_messages": int(attributes.get("ApproximateNumberOfMessages", 0)),
            "approximate_number_of_messages_not_visible": int(attributes.get("ApproximateNumberOfMessagesNotVisible", 0)),
            "approximate_number_of_messages_delayed": int(attributes.get("ApproximateNumberOfMessagesDelayed", 0)),
            "visibility_timeout": int(attributes.get("VisibilityTimeout", 0)),
            "maximum_message_size": int(attributes.get("MaximumMessageSize", 0)),
            "message_retention_period": int(attributes.get("MessageRetentionPeriod", 0)),
            "delay_seconds": int(attributes.get("DelaySeconds", 0)),
            "receive_message_wait_time_seconds": int(attributes.get("ReceiveMessageWaitTimeSeconds", 0)),
            "sqs_managed_sse_enabled": attributes.get("SqsManagedSseEnabled") == "true",
        }
        
        return normalized

