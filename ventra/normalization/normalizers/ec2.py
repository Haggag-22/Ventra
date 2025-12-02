"""
EC2 resource normalizer.

Normalizes EC2 instances, volumes, and snapshots from collector output.
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


class EC2Normalizer(BaseNormalizer):
    """
    Normalizes EC2 resources from collector JSON files.
    
    Handles:
    - ec2_instances*.json, ec2_volumes*.json, ec2_snapshots*.json, etc. (from resources/)
    """
    
    name = "ec2"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load EC2 data from collector JSON files."""
        # EC2 files are in resources/ subdirectory
        patterns = [
            "ec2_instances*.json",
            "ec2_volumes*.json",
            "ec2_snapshots*.json",
            "ec2_security_groups*.json",
            "ec2_network_interfaces*.json",
            "ec2_metadata_*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            return
        
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            # Yield the entire data structure as a single record
            # We'll normalize different resource types in normalize_record
            yield data
    
    def normalize_record(
        self, raw: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """
        Normalize EC2 resources.
        
        Returns a list of normalized resources (instance, volumes, snapshots).
        Actually returns None and handles multiple resources internally.
        """
        # This method will be called once per file, but we need to return
        # multiple resources. We'll handle this by saving multiple files.
        # For now, return None and handle in a custom way.
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        # Find files
        patterns = [
            "ec2_instances*.json",
            "ec2_volumes*.json",
            "ec2_snapshots*.json",
            "ec2_security_groups*.json",
            "ec2_network_interfaces*.json",
            "ec2_metadata_*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No EC2 data found")
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
                # Normalize instance
                instance_info = data.get("InstanceInfo")
                if instance_info:
                    instance = self._normalize_instance(instance_info, data, context)
                    if instance:
                        all_resources.append(instance)
                
                # Normalize volumes
                volumes = data.get("Volumes", [])
                for volume_data in volumes:
                    volume = self._normalize_volume(volume_data, context)
                    if volume:
                        all_resources.append(volume)
                
                # Normalize snapshots
                snapshots = data.get("Snapshots", [])
                for snapshot_data in snapshots:
                    snapshot = self._normalize_snapshot(snapshot_data, context)
                    if snapshot:
                        all_resources.append(snapshot)
            
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
    
    def _normalize_instance(
        self, instance_data: Dict[str, Any], all_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EC2 instance."""
        instance_id = instance_data.get("InstanceId")
        if not instance_id:
            return None
        
        # Extract ARN components
        arn = instance_data.get("InstanceArn")
        account_id = context.account_id
        region = context.region or instance_data.get("Placement", {}).get("AvailabilityZone", "")[:-1]
        
        if arn:
            parsed_arn = parse_arn(arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        # Generate resource ID
        resource_id = generate_resource_id(
            service="ec2",
            resource_type="instance",
            resource_identifier=instance_id,
            account_id=account_id,
            region=region,
        )
        
        # Extract tags
        tags = extract_tags(instance_data.get("Tags", []))
        
        # Extract state
        state = instance_data.get("State", {}).get("Name", "").lower()
        
        # Extract timestamps
        launch_time = normalize_timestamp(instance_data.get("LaunchTime"))
        
        # Build normalized instance
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EC2_INSTANCE,
            Fields.SERVICE: "ec2",
            Fields.RESOURCE_TYPE: "instance",
            Fields.RESOURCE_ID: instance_id,
            Fields.ARN: arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: tags.get("Name") or instance_id,
            Fields.STATE: state,
            Fields.CREATED_AT: launch_time,
            Fields.TAGS: tags,
            Fields.COLLECTED_AT: normalize_timestamp(all_data.get("CollectionTimestamp")),
        }
        
        # Add relationships
        relationships = []
        
        # Volume attachments
        volumes = all_data.get("Volumes", [])
        for volume_data in volumes:
            volume_id = volume_data.get("VolumeId")
            if volume_id:
                vol_resource_id = generate_resource_id(
                    service="ec2",
                    resource_type="volume",
                    resource_identifier=volume_id,
                    account_id=account_id,
                    region=region,
                )
                relationships.append({
                    "target_id": vol_resource_id,
                    "target_type": ResourceTypes.EC2_VOLUME,
                    "relationship_type": RelationshipTypes.ATTACHED_TO,
                })
        
        # IAM profile
        iam_profile = all_data.get("IamProfile")
        if iam_profile:
            profile_arn = iam_profile.get("Arn")
            if profile_arn:
                relationships.append({
                    "target_arn": profile_arn,
                    "target_type": ResourceTypes.IAM_ROLE,  # Instance profiles contain roles
                    "relationship_type": RelationshipTypes.USES,
                })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "instance_type": instance_data.get("InstanceType"),
            "image_id": instance_data.get("ImageId"),
            "key_name": instance_data.get("KeyName"),
            "vpc_id": instance_data.get("VpcId"),
            "subnet_id": instance_data.get("SubnetId"),
            "private_ip": instance_data.get("PrivateIpAddress"),
            "public_ip": instance_data.get("PublicIpAddress"),
            "security_groups": [
                {"group_id": sg.get("GroupId"), "group_name": sg.get("GroupName")}
                for sg in instance_data.get("SecurityGroups", [])
            ],
        }
        
        return normalized
    
    def _normalize_volume(
        self, volume_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EBS volume."""
        volume_id = volume_data.get("VolumeId")
        if not volume_id:
            return None
        
        account_id = context.account_id
        region = context.region or volume_data.get("AvailabilityZone", "")[:-1]
        
        resource_id = generate_resource_id(
            service="ec2",
            resource_type="volume",
            resource_identifier=volume_id,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(volume_data.get("Tags", []))
        create_time = normalize_timestamp(volume_data.get("CreateTime"))
        state = volume_data.get("State", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EC2_VOLUME,
            Fields.SERVICE: "ec2",
            Fields.RESOURCE_TYPE: "volume",
            Fields.RESOURCE_ID: volume_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: tags.get("Name") or volume_id,
            Fields.STATE: state,
            Fields.STATUS: state,  # Same as state for volumes
            Fields.CREATED_AT: create_time,
            Fields.TAGS: tags,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "size": volume_data.get("Size"),
            "volume_type": volume_data.get("VolumeType"),
            "encrypted": volume_data.get("Encrypted", False),
            "kms_key_id": volume_data.get("KmsKeyId"),
            "iops": volume_data.get("Iops"),
            "throughput": volume_data.get("Throughput"),
            "snapshot_id": volume_data.get("SnapshotId"),
            "multi_attach_enabled": volume_data.get("MultiAttachEnabled", False),
            "attachments": volume_data.get("Attachments", []),
        }
        
        return normalized
    
    def _normalize_snapshot(
        self, snapshot_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EBS snapshot."""
        snapshot_id = snapshot_data.get("SnapshotId")
        if not snapshot_id:
            return None
        
        account_id = context.account_id or snapshot_data.get("OwnerId")
        region = context.region or snapshot_data.get("StartTime", "")[:10]  # Approximate
        
        resource_id = generate_resource_id(
            service="ec2",
            resource_type="snapshot",
            resource_identifier=snapshot_id,
            account_id=account_id,
            region=region,
        )
        
        tags = extract_tags(snapshot_data.get("Tags", []))
        start_time = normalize_timestamp(snapshot_data.get("StartTime"))
        state = snapshot_data.get("State", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EC2_SNAPSHOT,
            Fields.SERVICE: "ec2",
            Fields.RESOURCE_TYPE: "snapshot",
            Fields.RESOURCE_ID: snapshot_id,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: tags.get("Name") or snapshot_id,
            Fields.STATE: state,
            Fields.STATUS: state,
            Fields.CREATED_AT: start_time,
            Fields.TAGS: tags,
        }
        
        # Add relationship to volume
        volume_id = snapshot_data.get("VolumeId")
        if volume_id:
            vol_resource_id = generate_resource_id(
                service="ec2",
                resource_type="volume",
                resource_identifier=volume_id,
                account_id=account_id,
                region=region,
            )
            normalized[Fields.RELATIONSHIPS] = [{
                "target_id": vol_resource_id,
                "target_type": ResourceTypes.EC2_VOLUME,
                "relationship_type": RelationshipTypes.CREATED_BY,
            }]
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "volume_id": volume_id,
            "volume_size": snapshot_data.get("VolumeSize"),
            "encrypted": snapshot_data.get("Encrypted", False),
            "kms_key_id": snapshot_data.get("KmsKeyId"),
            "description": snapshot_data.get("Description"),
            "owner_id": snapshot_data.get("OwnerId"),
            "owner_alias": snapshot_data.get("OwnerAlias"),
            "progress": snapshot_data.get("Progress"),
        }
        
        return normalized

