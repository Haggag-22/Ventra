"""
Lambda resource normalizer.

Normalizes Lambda functions from collector output.
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


class LambdaNormalizer(BaseNormalizer):
    """
    Normalizes Lambda functions from collector JSON files.
    
    Handles:
    - lambda_functions*.json, lambda_config*.json, lambda_env_vars*.json, etc. (from resources/)
    """
    
    name = "lambda"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load Lambda data from collector JSON files."""
        # Lambda files are in resources/ subdirectory
        patterns = [
            "lambda_functions*.json",
            "lambda_config*.json",
            "lambda_env_vars*.json",
            "lambda_policy*.json",
            "lambda_code*.json",
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
        """Normalize Lambda resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "lambda_functions*.json",
            "lambda_config*.json",
            "lambda_env_vars*.json",
            "lambda_policy*.json",
            "lambda_code*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No Lambda data found")
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
                # Handle different file structures
                functions = []
                if isinstance(data, list):
                    functions = data
                elif "functions" in data:
                    functions = data["functions"]
                elif "FunctionName" in data:
                    functions = [data]  # Single function
                
                for func_data in functions:
                    func = self._normalize_function(func_data, context)
                    if func:
                        all_resources.append(func)
            
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
    
    def _normalize_function(
        self, func_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a Lambda function."""
        function_name = func_data.get("FunctionName")
        if not function_name:
            return None
        
        function_arn = func_data.get("FunctionArn")
        account_id = context.account_id
        region = context.region
        
        if function_arn:
            parsed_arn = parse_arn(function_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="lambda",
            resource_type="function",
            resource_identifier=function_name,
            account_id=account_id,
            region=region,
        )
        
        last_modified = normalize_timestamp(func_data.get("LastModified"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.LAMBDA_FUNCTION,
            Fields.SERVICE: "lambda",
            Fields.RESOURCE_TYPE: "function",
            Fields.RESOURCE_ID: function_name,
            Fields.ARN: function_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: function_name,
            Fields.LAST_MODIFIED: last_modified,
        }
        
        # Add relationships
        relationships = []
        
        # IAM role relationship
        role_arn = func_data.get("Role")
        if role_arn:
            relationships.append({
                "target_arn": role_arn,
                "target_type": ResourceTypes.IAM_ROLE,
                "relationship_type": RelationshipTypes.USES,
            })
        
        # VPC relationship
        vpc_config = func_data.get("VpcConfig")
        if vpc_config and vpc_config.get("VpcId"):
            vpc_id = vpc_config.get("VpcId")
            vpc_resource_id = generate_resource_id(
                service="vpc",
                resource_type="vpc",
                resource_identifier=vpc_id,
                account_id=account_id,
                region=region,
            )
            relationships.append({
                "target_id": vpc_resource_id,
                "target_type": ResourceTypes.VPC,
                "relationship_type": RelationshipTypes.USES,
            })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "runtime": func_data.get("Runtime"),
            "handler": func_data.get("Handler"),
            "code_size": func_data.get("CodeSize", 0),
            "timeout": func_data.get("Timeout"),
            "memory_size": func_data.get("MemorySize"),
            "description": func_data.get("Description"),
            "package_type": func_data.get("PackageType"),
            "architectures": func_data.get("Architectures", []),
            "environment_variables": (func_data.get("Environment") or {}).get("Variables", {}),
            "kms_key_arn": func_data.get("KmsKeyArn"),
            "dead_letter_config": func_data.get("DeadLetterConfig"),
        }
        
        return normalized

