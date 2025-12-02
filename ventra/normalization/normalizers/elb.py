"""
ELB resource normalizer.

Normalizes ELB load balancers, target groups, and listeners from collector output.
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


class ELBNormalizer(BaseNormalizer):
    """
    Normalizes ELB resources from collector JSON files.
    
    Handles:
    - elb_all.json (from elb_all collector)
    """
    
    name = "elb"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load ELB data from collector JSON files."""
        # ELB files are in resources/ subdirectory (access logs are in events/)
        patterns = [
            "elb_access_logs*.json",
            "alb_access_logs*.json",
            "nlb_access_logs*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["events"])
        
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
        """Normalize ELB resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "elb_access_logs*.json",
            "alb_access_logs*.json",
            "nlb_access_logs*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["events"])
        
        if not files:
            print(f"    ⚠ No ELB data found")
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
                # Normalize ALB/NLB load balancers
                load_balancers_v2 = data.get("LoadBalancersV2", [])
                for lb_data in load_balancers_v2:
                    lb = self._normalize_load_balancer(lb_data, context)
                    if lb:
                        all_resources.append(lb)
                
                # Normalize Classic load balancers
                load_balancers_v1 = data.get("LoadBalancersV1", [])
                for lb_data in load_balancers_v1:
                    lb = self._normalize_load_balancer(lb_data, context)
                    if lb:
                        all_resources.append(lb)
                
                # Normalize target groups
                target_groups = data.get("TargetGroups", [])
                for tg_data in target_groups:
                    tg = self._normalize_target_group(tg_data, context)
                    if tg:
                        all_resources.append(tg)
            
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
    
    def _normalize_load_balancer(
        self, lb_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an ELB load balancer."""
        lb_arn = lb_data.get("LoadBalancerArn") or lb_data.get("LoadBalancerName")
        if not lb_arn:
            return None
        
        account_id = context.account_id
        region = context.region
        
        # For Classic ELB, use name instead of ARN
        if not lb_data.get("LoadBalancerArn"):
            lb_name = lb_data.get("LoadBalancerName")
            lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb_name}"
        else:
            parsed_arn = parse_arn(lb_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        lb_name = lb_data.get("LoadBalancerName") or lb_arn.split("/")[-1]
        
        resource_id = generate_resource_id(
            service="elb",
            resource_type="load_balancer",
            resource_identifier=lb_name,
            account_id=account_id,
            region=region,
        )
        
        state = lb_data.get("State", {}).get("Code", "").lower() if isinstance(lb_data.get("State"), dict) else lb_data.get("State", "").lower()
        created_time = normalize_timestamp(lb_data.get("CreatedTime"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.ELB_LOAD_BALANCER,
            Fields.SERVICE: "elb",
            Fields.RESOURCE_TYPE: "load_balancer",
            Fields.RESOURCE_ID: lb_name,
            Fields.ARN: lb_arn if lb_data.get("LoadBalancerArn") else None,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: lb_name,
            Fields.STATE: state,
            Fields.STATUS: state,
            Fields.CREATED_AT: created_time,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "type": lb_data.get("Type") or "classic",
            "scheme": lb_data.get("Scheme"),
            "dns_name": lb_data.get("DNSName"),
            "vpc_id": lb_data.get("VpcId"),
            "availability_zones": lb_data.get("AvailabilityZones", []),
            "security_groups": lb_data.get("SecurityGroups", []),
        }
        
        return normalized
    
    def _normalize_target_group(
        self, tg_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an ELB target group."""
        tg_arn = tg_data.get("TargetGroupArn")
        if not tg_arn:
            return None
        
        parsed_arn = parse_arn(tg_arn)
        account_id = context.account_id
        region = context.region
        
        if parsed_arn:
            account_id = parsed_arn.get("account_id") or account_id
            region = parsed_arn.get("region") or region
        
        tg_name = tg_data.get("TargetGroupName") or tg_arn.split("/")[-1]
        
        resource_id = generate_resource_id(
            service="elb",
            resource_type="target_group",
            resource_identifier=tg_name,
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.ELB_TARGET_GROUP,
            Fields.SERVICE: "elb",
            Fields.RESOURCE_TYPE: "target_group",
            Fields.RESOURCE_ID: tg_name,
            Fields.ARN: tg_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: tg_name,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "protocol": tg_data.get("Protocol"),
            "port": tg_data.get("Port"),
            "vpc_id": tg_data.get("VpcId"),
            "health_check_protocol": tg_data.get("HealthCheckProtocol"),
            "health_check_path": tg_data.get("HealthCheckPath"),
            "target_type": tg_data.get("TargetType"),
        }
        
        return normalized

