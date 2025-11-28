"""
DynamoDB resource normalizer.

Normalizes DynamoDB tables, backups, and items from collector output.
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


class DynamoDBNormalizer(BaseNormalizer):
    """
    Normalizes DynamoDB resources from collector JSON files.
    
    Handles:
    - dynamodb_*_all.json (from dynamodb_all collector)
    """
    
    name = "dynamodb"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load DynamoDB data from collector JSON files."""
        patterns = ["dynamodb_*_all.json"]
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
        """Normalize DynamoDB resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = ["dynamodb_*_all.json"]
        files = self.find_collector_files(context, patterns)
        
        if not files:
            print(f"    ⚠ No DynamoDB data found")
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
                # Normalize table
                table_info = data.get("TableInfo")
                if table_info:
                    table = self._normalize_table(table_info, data, context)
                    if table:
                        all_resources.append(table)
                
                # Normalize backups
                backups = data.get("Backups", [])
                for backup_data in backups:
                    backup = self._normalize_backup(backup_data, context)
                    if backup:
                        all_resources.append(backup)
            
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
    
    def _normalize_table(
        self, table_info: Dict[str, Any], all_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a DynamoDB table."""
        table_name = table_info.get("TableName")
        if not table_name:
            return None
        
        table_arn = table_info.get("TableArn")
        account_id = context.account_id
        region = context.region
        
        if table_arn:
            parsed_arn = parse_arn(table_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="dynamodb",
            resource_type="table",
            resource_identifier=table_name,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(table_info.get("Tags", {}))
        create_time = normalize_timestamp(table_info.get("CreationDateTime"))
        status = table_info.get("TableStatus", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.DYNAMODB_TABLE,
            Fields.SERVICE: "dynamodb",
            Fields.RESOURCE_TYPE: "table",
            Fields.RESOURCE_ID: table_name,
            Fields.ARN: table_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: table_name,
            Fields.STATUS: status,
            Fields.STATE: status,  # Same as status
            Fields.CREATED_AT: create_time,
            Fields.TAGS: tags,
        }
        
        # Add relationships
        relationships = []
        
        # Backups
        backups = all_data.get("Backups", [])
        for backup_data in backups:
            backup_arn = backup_data.get("BackupArn")
            if backup_arn:
                backup_resource_id = generate_resource_id(
                    service="dynamodb",
                    resource_type="backup",
                    resource_identifier=backup_arn.split("/")[-1],
                    account_id=account_id,
                    region=region,
                )
                relationships.append({
                    "target_id": backup_resource_id,
                    "target_type": ResourceTypes.DYNAMODB_BACKUP,
                    "relationship_type": RelationshipTypes.CREATED_BY,
                })
        
        # Streams
        streams = all_data.get("Streams", [])
        for stream_data in streams:
            stream_arn = stream_data.get("StreamArn")
            if stream_arn:
                relationships.append({
                    "target_arn": stream_arn,
                    "target_type": "aws.dynamodb.stream",
                    "relationship_type": RelationshipTypes.USES,
                })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "table_size_bytes": table_info.get("TableSizeBytes", 0),
            "item_count": table_info.get("ItemCount", 0),
            "attribute_definitions": table_info.get("AttributeDefinitions", []),
            "key_schema": table_info.get("KeySchema", []),
            "billing_mode": table_info.get("BillingModeSummary", {}).get("BillingMode"),
            "provisioned_throughput": table_info.get("ProvisionedThroughput"),
            "global_secondary_indexes": len(table_info.get("GlobalSecondaryIndexes", [])),
            "local_secondary_indexes": len(table_info.get("LocalSecondaryIndexes", [])),
            "stream_enabled": bool(table_info.get("StreamSpecification", {}).get("StreamEnabled")),
            "stream_arn": table_info.get("LatestStreamArn"),
            "sse_description": table_info.get("SSEDescription"),
            "table_class": table_info.get("TableClass"),
            "item_count_from_collection": len(all_data.get("Items", [])),
        }
        
        return normalized
    
    def _normalize_backup(
        self, backup_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a DynamoDB backup."""
        backup_arn = backup_data.get("BackupArn")
        if not backup_arn:
            return None
        
        table_name = backup_data.get("TableName")
        backup_name = backup_data.get("BackupName") or backup_arn.split("/")[-1]
        
        parsed_arn = parse_arn(backup_arn)
        account_id = context.account_id
        region = context.region
        
        if parsed_arn:
            account_id = parsed_arn.get("account_id") or account_id
            region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="dynamodb",
            resource_type="backup",
            resource_identifier=backup_name,
            account_id=account_id,
            region=region,
        )
        
        create_time = normalize_timestamp(backup_data.get("BackupCreationDateTime"))
        expiry_time = normalize_timestamp(backup_data.get("BackupExpiryDateTime"))
        status = backup_data.get("BackupStatus", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.DYNAMODB_BACKUP,
            Fields.SERVICE: "dynamodb",
            Fields.RESOURCE_TYPE: "backup",
            Fields.RESOURCE_ID: backup_name,
            Fields.ARN: backup_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: backup_name,
            Fields.STATUS: status,
            Fields.STATE: status,
            Fields.CREATED_AT: create_time,
            Fields.DELETED_AT: expiry_time,  # Expiry is effectively deletion
        }
        
        # Add relationship to table
        if table_name:
            table_resource_id = generate_resource_id(
                service="dynamodb",
                resource_type="table",
                resource_identifier=table_name,
                account_id=account_id,
                region=region,
            )
            normalized[Fields.RELATIONSHIPS] = [{
                "target_id": table_resource_id,
                "target_type": ResourceTypes.DYNAMODB_TABLE,
                "relationship_type": RelationshipTypes.CREATED_BY,
            }]
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "table_name": table_name,
            "table_arn": backup_data.get("TableArn"),
            "backup_type": backup_data.get("BackupType"),
            "backup_size_bytes": backup_data.get("BackupSizeBytes", 0),
        }
        
        return normalized

