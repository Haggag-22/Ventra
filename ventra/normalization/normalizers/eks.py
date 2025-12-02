"""
EKS resource normalizer.

Normalizes EKS clusters and nodegroups from collector output.
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


class EKSNormalizer(BaseNormalizer):
    """
    Normalizes EKS resources from collector JSON files.
    
    Handles:
    - eks_*_all.json (from eks_all collector)
    """
    
    name = "eks"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load EKS data from collector JSON files."""
        # EKS files are in resources/ subdirectory
        patterns = [
            "eks_clusters*.json",
            "eks_nodegroups*.json",
            "eks_security*.json",
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
        """Normalize EKS resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "eks_clusters*.json",
            "eks_nodegroups*.json",
            "eks_security*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No EKS data found")
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
                # Normalize cluster
                cluster_info = data.get("ClusterInfo")
                if cluster_info:
                    cluster = self._normalize_cluster(cluster_info, data, context)
                    if cluster:
                        all_resources.append(cluster)
                
                # Normalize nodegroups
                nodegroups = data.get("Nodegroups", [])
                for ng_data in nodegroups:
                    ng = self._normalize_nodegroup(ng_data, data, context)
                    if ng:
                        all_resources.append(ng)
            
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
    
    def _normalize_cluster(
        self, cluster_info: Dict[str, Any], all_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EKS cluster."""
        cluster_name = cluster_info.get("Name")
        if not cluster_name:
            return None
        
        cluster_arn = cluster_info.get("Arn")
        account_id = context.account_id
        region = context.region
        
        if cluster_arn:
            parsed_arn = parse_arn(cluster_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="eks",
            resource_type="cluster",
            resource_identifier=cluster_name,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(cluster_info.get("Tags", {}))
        created_at = normalize_timestamp(cluster_info.get("CreatedAt"))
        status = cluster_info.get("Status", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EKS_CLUSTER,
            Fields.SERVICE: "eks",
            Fields.RESOURCE_TYPE: "cluster",
            Fields.RESOURCE_ID: cluster_name,
            Fields.ARN: cluster_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: cluster_name,
            Fields.STATUS: status,
            Fields.STATE: status,
            Fields.CREATED_AT: created_at,
            Fields.TAGS: tags,
        }
        
        # Add relationships
        relationships = []
        
        # VPC relationship
        vpc_config = cluster_info.get("ResourcesVpcConfig", {})
        vpc_id = vpc_config.get("vpcId")
        if vpc_id:
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
        
        # IAM role relationship
        role_arn = cluster_info.get("RoleArn")
        if role_arn:
            relationships.append({
                "target_arn": role_arn,
                "target_type": ResourceTypes.IAM_ROLE,
                "relationship_type": RelationshipTypes.USES,
            })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "version": cluster_info.get("Version"),
            "endpoint": cluster_info.get("Endpoint"),
            "nodegroups_count": len(all_data.get("Nodegroups", [])),
            "fargate_profiles_count": len(all_data.get("FargateProfiles", [])),
            "addons_count": len(all_data.get("Addons", [])),
            "endpoint_public_access": vpc_config.get("endpointPublicAccess", False),
            "endpoint_private_access": vpc_config.get("endpointPrivateAccess", False),
        }
        
        return normalized
    
    def _normalize_nodegroup(
        self, ng_data: Dict[str, Any], all_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EKS nodegroup."""
        ng_name = ng_data.get("NodegroupName")
        if not ng_name:
            return None
        
        cluster_name = all_data.get("ClusterName")
        ng_arn = ng_data.get("NodegroupArn")
        
        account_id = context.account_id
        region = context.region
        
        if ng_arn:
            parsed_arn = parse_arn(ng_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="eks",
            resource_type="nodegroup",
            resource_identifier=f"{cluster_name}/{ng_name}",
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(ng_data.get("Tags", {}))
        created_at = normalize_timestamp(ng_data.get("CreatedAt"))
        status = ng_data.get("Status", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EKS_NODEGROUP,
            Fields.SERVICE: "eks",
            Fields.RESOURCE_TYPE: "nodegroup",
            Fields.RESOURCE_ID: ng_name,
            Fields.ARN: ng_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: ng_name,
            Fields.STATUS: status,
            Fields.STATE: status,
            Fields.CREATED_AT: created_at,
            Fields.TAGS: tags,
        }
        
        # Add relationship to cluster
        if cluster_name:
            cluster_resource_id = generate_resource_id(
                service="eks",
                resource_type="cluster",
                resource_identifier=cluster_name,
                account_id=account_id,
                region=region,
            )
            normalized[Fields.RELATIONSHIPS] = [{
                "target_id": cluster_resource_id,
                "target_type": ResourceTypes.EKS_CLUSTER,
                "relationship_type": RelationshipTypes.CONTAINS,
            }]
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "cluster_name": cluster_name,
            "instance_types": ng_data.get("InstanceTypes", []),
            "scaling_config": ng_data.get("ScalingConfig", {}),
            "ami_type": ng_data.get("AmiType"),
            "node_role": ng_data.get("NodeRole"),
            "capacity_type": ng_data.get("CapacityType"),
        }
        
        return normalized

