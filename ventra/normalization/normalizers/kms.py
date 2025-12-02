"""
KMS resource normalizer.

Normalizes KMS keys from collector output.
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


class KMSNormalizer(BaseNormalizer):
    """
    Normalizes KMS keys from collector JSON files.
    
    Handles:
    - kms.json
    """
    
    name = "kms"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load KMS data from collector JSON files."""
        # KMS files are in resources/ subdirectory
        patterns = ["kms_keys*.json"]
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
        """Normalize KMS resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = ["kms_keys*.json"]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No KMS data found")
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
                # Handle keys array
                keys = data.get("keys", [])
                for key_data in keys:
                    key = self._normalize_key(key_data, context)
                    if key:
                        all_resources.append(key)
            
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
    
    def _normalize_key(
        self, key_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a KMS key."""
        key_id = key_data.get("KeyId")
        if not key_id:
            return None
        
        key_arn = key_data.get("Arn")
        account_id = context.account_id
        region = context.region
        
        if key_arn:
            parsed_arn = parse_arn(key_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="kms",
            resource_type="key",
            resource_identifier=key_id,
            account_id=account_id,
            region=region,
        )
        
        created_at = normalize_timestamp(key_data.get("CreationDate"))
        deletion_date = normalize_timestamp(key_data.get("DeletionDate"))
        key_state = key_data.get("KeyState", "").lower()
        enabled = key_data.get("Enabled", False)
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.KMS_KEY,
            Fields.SERVICE: "kms",
            Fields.RESOURCE_TYPE: "key",
            Fields.RESOURCE_ID: key_id,
            Fields.ARN: key_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: key_data.get("Description") or key_id,
            Fields.STATE: key_state if key_state else ("enabled" if enabled else "disabled"),
            Fields.STATUS: key_state if key_state else ("enabled" if enabled else "disabled"),
            Fields.CREATED_AT: created_at,
            Fields.DELETED_AT: deletion_date,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "description": key_data.get("Description"),
            "key_usage": key_data.get("KeyUsage"),
            "key_spec": key_data.get("KeySpec"),
            "key_manager": key_data.get("KeyManager"),
            "origin": key_data.get("Origin"),
            "enabled": enabled,
            "customer_master_key_spec": key_data.get("CustomerMasterKeySpec"),
            "encryption_algorithms": key_data.get("EncryptionAlgorithms", []),
        }
        
        return normalized

