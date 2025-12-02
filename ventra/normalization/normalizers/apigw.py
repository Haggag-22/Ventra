"""
API Gateway resource normalizer.

Normalizes API Gateway REST APIs, stages, and resources from collector output.
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


class APIGWNormalizer(BaseNormalizer):
    """
    Normalizes API Gateway resources from collector JSON files.
    
    Handles:
    - apigw_all.json (from apigw_all collector)
    """
    
    name = "apigw"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load API Gateway data from collector JSON files."""
        # API Gateway files are in resources/ subdirectory
        patterns = [
            "apigw_rest_apis*.json",
            "apigw_integrations*.json",
            "apigw_routes*.json",
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
        """Normalize API Gateway resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "apigw_rest_apis*.json",
            "apigw_integrations*.json",
            "apigw_routes*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No API Gateway data found")
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
                # Normalize APIs
                apis = data.get("apis", [])
                for api_data_item in apis:
                    api_info = api_data_item.get("ApiInfo")
                    if api_info:
                        api = self._normalize_api(api_info, api_data_item, context)
                        if api:
                            all_resources.append(api)
            
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
    
    def _normalize_api(
        self, api_info: Dict[str, Any], api_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an API Gateway REST API."""
        api_id = api_info.get("Id")
        if not api_id:
            return None
        
        api_name = api_info.get("Name")
        account_id = context.account_id
        region = context.region
        
        # Construct ARN
        api_arn = f"arn:aws:apigateway:{region}:{account_id}:/restapis/{api_id}"
        
        resource_id = generate_resource_id(
            service="apigw",
            resource_type="rest_api",
            resource_identifier=api_id,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(api_info.get("Tags", {}))
        created_date = normalize_timestamp(api_info.get("CreatedDate"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.APIGW_REST_API,
            Fields.SERVICE: "apigw",
            Fields.RESOURCE_TYPE: "rest_api",
            Fields.RESOURCE_ID: api_id,
            Fields.ARN: api_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: api_name or api_id,
            Fields.CREATED_AT: created_date,
            Fields.TAGS: tags,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "description": api_info.get("Description"),
            "version": api_info.get("Version"),
            "api_key_source": api_info.get("ApiKeySource"),
            "endpoint_configuration": api_info.get("EndpointConfiguration", {}),
            "routes_count": len(api_data.get("Routes", {}).get("Resources", [])),
            "stages_count": len(api_data.get("Stages", [])),
        }
        
        return normalized

