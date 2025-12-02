"""
S3 resource normalizer.

Normalizes S3 buckets and objects from collector output.
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


class S3Normalizer(BaseNormalizer):
    """
    Normalizes S3 resources from collector JSON files.
    
    Handles:
    - s3_buckets*.json, s3_objects*.json, s3_versions*.json, s3_bucket_policies*.json (from resources/)
    - s3_access_logs*.json (from events/)
    """
    
    name = "s3"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load S3 data from collector JSON files."""
        # S3 resource files are in resources/, access logs are in events/
        patterns = [
            "s3_buckets*.json",
            "s3_objects*.json",
            "s3_versions*.json",
            "s3_bucket_policies*.json",
            "s3_access_logs*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources", "events"])
        
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
        """Normalize S3 resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "s3_buckets*.json",
            "s3_objects*.json",
            "s3_versions*.json",
            "s3_bucket_policies*.json",
            "s3_access_logs*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources", "events"])
        
        if not files:
            print(f"    ⚠ No S3 data found")
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
                # Normalize bucket
                bucket_name = data.get("BucketName")
                if bucket_name:
                    bucket = self._normalize_bucket(data, context)
                    if bucket:
                        all_resources.append(bucket)
                
                # Normalize objects
                objects_data = data.get("Objects", {})
                objects_list = objects_data.get("objects", [])
                for obj_data in objects_list:
                    obj = self._normalize_object(obj_data, bucket_name, data, context)
                    if obj:
                        all_resources.append(obj)
            
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
    
    def _normalize_bucket(
        self, data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an S3 bucket."""
        bucket_name = data.get("BucketName")
        if not bucket_name:
            return None
        
        bucket_info = data.get("BucketInfo", {})
        location = bucket_info.get("location") or context.region or "us-east-1"
        account_id = context.account_id
        
        # Try to extract from bucket ARN if available
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        
        resource_id = generate_resource_id(
            service="s3",
            resource_type="bucket",
            resource_identifier=bucket_name,
            account_id=account_id,
            region="",  # S3 buckets are global
        )
        
        # Extract tags
        tags = extract_tags(bucket_info.get("tags", {}))
        
        # Extract versioning status
        versioning = bucket_info.get("versioning", {})
        versioning_status = versioning.get("Status", "NotEnabled")
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.S3_BUCKET,
            Fields.SERVICE: "s3",
            Fields.RESOURCE_TYPE: "bucket",
            Fields.RESOURCE_ID: bucket_name,
            Fields.ARN: bucket_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: "",  # S3 buckets are global
            Fields.NAME: bucket_name,
            Fields.STATE: "available",  # Assume available if we can read it
            Fields.TAGS: tags,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "location": location,
            "versioning_enabled": versioning_status == "Enabled",
            "encryption": bucket_info.get("encryption", {}),
            "public_access_block": bucket_info.get("public_access_block", {}),
            "lifecycle_rules": len(bucket_info.get("lifecycle", [])),
            "cors_enabled": len(bucket_info.get("cors", [])) > 0,
            "website_enabled": bool(bucket_info.get("website")),
            "object_count": data.get("Objects", {}).get("total_objects", 0),
            "is_public": data.get("Access", {}).get("public_access", {}).get("is_public", False),
        }
        
        return normalized
    
    def _normalize_object(
        self, obj_data: Dict[str, Any], bucket_name: str, bucket_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an S3 object."""
        key = obj_data.get("Key")
        if not key:
            return None
        
        account_id = context.account_id
        location = bucket_data.get("BucketInfo", {}).get("location") or context.region or "us-east-1"
        
        resource_id = generate_resource_id(
            service="s3",
            resource_type="object",
            resource_identifier=f"{bucket_name}/{key}",
            account_id=account_id,
            region="",
        )
        
        last_modified = normalize_timestamp(obj_data.get("LastModified"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.S3_OBJECT,
            Fields.SERVICE: "s3",
            Fields.RESOURCE_TYPE: "object",
            Fields.RESOURCE_ID: f"{bucket_name}/{key}",
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: "",
            Fields.NAME: key,
            Fields.LAST_MODIFIED: last_modified,
        }
        
        # Add relationship to bucket
        bucket_resource_id = generate_resource_id(
            service="s3",
            resource_type="bucket",
            resource_identifier=bucket_name,
            account_id=account_id,
            region="",
        )
        normalized[Fields.RELATIONSHIPS] = [{
            "target_id": bucket_resource_id,
            "target_type": ResourceTypes.S3_BUCKET,
            "relationship_type": RelationshipTypes.CONTAINS,
        }]
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "bucket_name": bucket_name,
            "key": key,
            "size": obj_data.get("Size", 0),
            "storage_class": obj_data.get("StorageClass"),
            "etag": obj_data.get("ETag"),
        }
        
        return normalized

