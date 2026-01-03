"""
VPC resource normalizer.

Normalizes VPCs, subnets, and security groups from collector output.
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


class VPCNormalizer(BaseNormalizer):
    """
    Normalizes VPC resources from collector JSON files.
    
    Handles:
    - vpc*.json, vpc_subnets*.json, vpc_route_tables*.json, etc. (from resources/)
    """
    
    name = "vpc"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load VPC data from collector JSON files."""
        # VPC resource files are in resources/, flow logs are in events/
        patterns = [
            "vpc*.json",
            "vpc_subnets*.json",
            "vpc_route_tables*.json",
            "vpc_security_groups*.json",
            "vpc_network_acls*.json",
            "vpc_flow_logs*.json",
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
        """Normalize VPC resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "vpc*.json",
            "vpc_subnets*.json",
            "vpc_route_tables*.json",
            "vpc_security_groups*.json",
            "vpc_network_acls*.json",
            "vpc_flow_logs*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources", "logs"])
        
        if not files:
            print(f"    ⚠ No VPC data found")
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
                # Normalize VPCs
                vpcs = data.get("VPCs", [])
                for vpc_data in vpcs:
                    vpc = self._normalize_vpc(vpc_data, data, context)
                    if vpc:
                        all_resources.append(vpc)
                
                # Normalize subnets
                subnets = data.get("Subnets", [])
                for subnet_data in subnets:
                    subnet = self._normalize_subnet(subnet_data, context)
                    if subnet:
                        all_resources.append(subnet)
                
                # Normalize security groups
                security_groups = data.get("SecurityGroups", [])
                for sg_data in security_groups:
                    sg = self._normalize_security_group(sg_data, context)
                    if sg:
                        all_resources.append(sg)
            
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
    
    def _normalize_vpc(
        self, vpc_data: Dict[str, Any], all_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a VPC."""
        vpc_id = vpc_data.get("VpcId")
        if not vpc_id:
            return None
        
        account_id = context.account_id or vpc_data.get("OwnerId")
        region = context.region
        
        resource_id = generate_resource_id(
            service="vpc",
            resource_type="vpc",
            resource_identifier=vpc_id,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(vpc_data.get("Tags", []))
        state = vpc_data.get("State", "").lower()
        cidr_block = vpc_data.get("CidrBlock")
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.VPC,
            Fields.SERVICE: "vpc",
            Fields.RESOURCE_TYPE: "vpc",
            Fields.RESOURCE_ID: vpc_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: tags.get("Name") or vpc_id,
            Fields.STATE: state,
            Fields.STATUS: state,
            Fields.TAGS: tags,
        }
        
        # Add relationships
        relationships = []
        
        # Subnets
        subnets = all_data.get("Subnets", [])
        for subnet_data in subnets:
            if subnet_data.get("VpcId") == vpc_id:
                subnet_id = subnet_data.get("SubnetId")
                if subnet_id:
                    subnet_resource_id = generate_resource_id(
                        service="vpc",
                        resource_type="subnet",
                        resource_identifier=subnet_id,
                        account_id=account_id,
                        region=region,
                    )
                    relationships.append({
                        "target_id": subnet_resource_id,
                        "target_type": ResourceTypes.VPC_SUBNET,
                        "relationship_type": RelationshipTypes.CONTAINS,
                    })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "cidr_block": cidr_block,
            "is_default": vpc_data.get("IsDefault", False),
            "instance_tenancy": vpc_data.get("InstanceTenancy"),
            "dhcp_options_id": vpc_data.get("DhcpOptionsId"),
            "subnets_count": len([s for s in subnets if s.get("VpcId") == vpc_id]),
        }
        
        return normalized
    
    def _normalize_subnet(
        self, subnet_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a VPC subnet."""
        subnet_id = subnet_data.get("SubnetId")
        if not subnet_id:
            return None
        
        vpc_id = subnet_data.get("VpcId")
        account_id = context.account_id or subnet_data.get("OwnerId")
        region = context.region or subnet_data.get("AvailabilityZone", "")[:-1]
        
        resource_id = generate_resource_id(
            service="vpc",
            resource_type="subnet",
            resource_identifier=subnet_id,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(subnet_data.get("Tags", []))
        state = subnet_data.get("State", "").lower()
        cidr_block = subnet_data.get("CidrBlock")
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.VPC_SUBNET,
            Fields.SERVICE: "vpc",
            Fields.RESOURCE_TYPE: "subnet",
            Fields.RESOURCE_ID: subnet_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: tags.get("Name") or subnet_id,
            Fields.STATE: state,
            Fields.STATUS: state,
            Fields.TAGS: tags,
        }
        
        # Add relationship to VPC
        if vpc_id:
            vpc_resource_id = generate_resource_id(
                service="vpc",
                resource_type="vpc",
                resource_identifier=vpc_id,
                account_id=account_id,
                region=region,
            )
            normalized[Fields.RELATIONSHIPS] = [{
                "target_id": vpc_resource_id,
                "target_type": ResourceTypes.VPC,
                "relationship_type": RelationshipTypes.CONTAINS,
            }]
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "vpc_id": vpc_id,
            "cidr_block": cidr_block,
            "availability_zone": subnet_data.get("AvailabilityZone"),
            "available_ip_address_count": subnet_data.get("AvailableIpAddressCount"),
            "map_public_ip_on_launch": subnet_data.get("MapPublicIpOnLaunch", False),
        }
        
        return normalized
    
    def _normalize_security_group(
        self, sg_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a VPC security group."""
        group_id = sg_data.get("GroupId")
        if not group_id:
            return None
        
        vpc_id = sg_data.get("VpcId")
        account_id = context.account_id
        region = context.region
        
        resource_id = generate_resource_id(
            service="vpc",
            resource_type="security_group",
            resource_identifier=group_id,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(sg_data.get("Tags", []))
        group_name = sg_data.get("GroupName")
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.VPC_SECURITY_GROUP,
            Fields.SERVICE: "vpc",
            Fields.RESOURCE_TYPE: "security_group",
            Fields.RESOURCE_ID: group_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: group_name or group_id,
            Fields.TAGS: tags,
        }
        
        # Add relationship to VPC
        if vpc_id:
            vpc_resource_id = generate_resource_id(
                service="vpc",
                resource_type="vpc",
                resource_identifier=vpc_id,
                account_id=account_id,
                region=region,
            )
            normalized[Fields.RELATIONSHIPS] = [{
                "target_id": vpc_resource_id,
                "target_type": ResourceTypes.VPC,
                "relationship_type": RelationshipTypes.CONTAINS,
            }]
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "vpc_id": vpc_id,
            "description": sg_data.get("Description"),
            "inbound_rules_count": len(sg_data.get("IpPermissions", [])),
            "outbound_rules_count": len(sg_data.get("IpPermissionsEgress", [])),
        }
        
        return normalized

