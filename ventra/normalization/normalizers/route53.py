"""
Route53 resource normalizer.

Normalizes Route53 hosted zones and DNS records from collector output.
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


class Route53Normalizer(BaseNormalizer):
    """
    Normalizes Route53 resources from collector JSON files.
    
    Handles:
    - route53_hosted_zones*.json (from resources/)
    - route53_records*.json (from resources/)
    - route53_resolver_query_logs.json (from logs/)
    """
    
    name = "route53"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load Route53 data from collector JSON files."""
        # Route53 resource files are in resources/, query logs are in events/
        patterns = [
            "route53_hosted_zones*.json",
            "route53_records*.json",
            "route53_resolver_query_logs.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources", "logs"])
        
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
        """Normalize Route53 resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "route53_hosted_zones*.json",
            "route53_records*.json",
            "route53_resolver_query_logs.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources", "logs"])
        
        if not files:
            print(f"    ⚠ No Route53 data found")
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
                # Handle hosted zones
                hosted_zones = data.get("HostedZones", [])
                for zone_data in hosted_zones:
                    zone = self._normalize_hosted_zone(zone_data, context)
                    if zone:
                        all_resources.append(zone)
                
                # Handle DNS records
                resource_record_sets = data.get("ResourceRecordSets", [])
                zone_id = data.get("HostedZoneId") or data.get("ZoneId")
                for record_data in resource_record_sets:
                    record = self._normalize_dns_record(record_data, zone_id, context)
                    if record:
                        all_resources.append(record)
                
                # Handle query logs
                query_logs = data.get("ResolverQueryLogConfigs", [])
                for log_data in query_logs:
                    log_config = self._normalize_query_log(log_data, context)
                    if log_config:
                        all_resources.append(log_config)
            
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
    
    def _normalize_hosted_zone(
        self, zone_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a Route53 hosted zone."""
        zone_id = zone_data.get("Id", "").split("/")[-1] if zone_data.get("Id") else None
        zone_name = zone_data.get("Name")
        
        if not zone_id or not zone_name:
            return None
        
        account_id = context.account_id
        region = "us-east-1"  # Route53 is global but API is in us-east-1
        
        resource_id = generate_resource_id(
            service="route53",
            resource_type="hosted_zone",
            resource_identifier=zone_id,
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.ROUTE53_HOSTED_ZONE,
            Fields.SERVICE: "route53",
            Fields.RESOURCE_TYPE: "hosted_zone",
            Fields.RESOURCE_ID: zone_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: zone_name.rstrip("."),
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "caller_reference": zone_data.get("CallerReference"),
            "config": zone_data.get("Config", {}),
            "resource_record_set_count": zone_data.get("ResourceRecordSetCount", 0),
        }
        
        return normalized
    
    def _normalize_record(
        self, record_data: Dict[str, Any], zone_id: Optional[str], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a Route53 DNS record."""
        record_name = record_data.get("Name")
        record_type = record_data.get("Type")
        
        if not record_name or not record_type:
            return None
        
        account_id = context.account_id
        region = "us-east-1"
        
        resource_id = generate_resource_id(
            service="route53",
            resource_type="dns_record",
            resource_identifier=f"{zone_id or 'unknown'}/{record_name}/{record_type}",
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.ROUTE53_RECORD,
            Fields.SERVICE: "route53",
            Fields.RESOURCE_TYPE: "dns_record",
            Fields.RESOURCE_ID: f"{record_name}/{record_type}",
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: record_name.rstrip("."),
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "type": record_type,
            "ttl": record_data.get("TTL"),
            "resource_records": record_data.get("ResourceRecords", []),
            "alias_target": record_data.get("AliasTarget"),
            "health_check_id": record_data.get("HealthCheckId"),
            "set_identifier": record_data.get("SetIdentifier"),
            "failover": record_data.get("Failover"),
            "multi_value_answer": record_data.get("MultiValueAnswer"),
            "weight": record_data.get("Weight"),
            "region": record_data.get("Region"),
            "geo_location": record_data.get("GeoLocation"),
        }
        
        return normalized
    
    def _normalize_query_log(
        self, log_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a Route53 Resolver query log configuration."""
        log_id = log_data.get("Id")
        log_name = log_data.get("Name")
        
        if not log_id:
            return None
        
        account_id = context.account_id
        region = context.region or "us-east-1"
        
        resource_id = generate_resource_id(
            service="route53",
            resource_type="resolver_query_log",
            resource_identifier=log_id,
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.ROUTE53_RESOLVER_QUERY_LOG,
            Fields.SERVICE: "route53",
            Fields.RESOURCE_TYPE: "resolver_query_log",
            Fields.RESOURCE_ID: log_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: log_name or log_id,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "arn": log_data.get("Arn"),
            "destination_arn": log_data.get("DestinationArn"),
            "status": log_data.get("Status"),
            "share_status": log_data.get("ShareStatus"),
            "association_count": log_data.get("AssociationCount", 0),
            "creator_request_id": log_data.get("CreatorRequestId"),
        }
        
        return normalized

