"""
IAM resource normalizer.

Normalizes IAM users, roles, groups, and policies from collector output.
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
)


class IAMNormalizer(BaseNormalizer):
    """
    Normalizes IAM resources from collector JSON files.
    
    Handles:
    - iam_users*.json, iam_roles*.json, iam_policies*.json, iam_groups*.json (from resources/)
    """
    
    name = "iam"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load IAM data from collector JSON files."""
        # IAM files are in resources/ subdirectory
        patterns = [
            "iam_users*.json",
            "iam_roles*.json",
            "iam_policies*.json",
            "iam_groups*.json",
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
        """Normalize IAM resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = [
            "iam_users*.json",
            "iam_roles*.json",
            "iam_policies*.json",
            "iam_groups*.json",
        ]
        files = self.find_collector_files(context, patterns, subdirs=["resources"])
        
        if not files:
            print(f"    ⚠ No IAM data found")
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
                # Normalize users
                users = data.get("all_users", [])
                users_detail = data.get("users_detail", {})
                for user_data in users:
                    username = user_data.get("UserName")
                    user_detail = users_detail.get(username, {})
                    user = self._normalize_user(user_data, user_detail, context)
                    if user:
                        all_resources.append(user)
                
                # Normalize roles
                roles = data.get("all_roles", [])
                roles_detail = data.get("roles_detail", {})
                for role_data in roles:
                    role_name = role_data.get("RoleName")
                    role_detail = roles_detail.get(role_name, {})
                    role = self._normalize_role(role_data, role_detail, context)
                    if role:
                        all_resources.append(role)
                
                # Normalize groups
                groups = data.get("all_groups", [])
                groups_detail = data.get("groups_detail", {})
                for group_data in groups:
                    group_name = group_data.get("GroupName")
                    group_detail = groups_detail.get(group_name, {})
                    group = self._normalize_group(group_data, group_detail, context)
                    if group:
                        all_resources.append(group)
                
                # Normalize policies
                policies = data.get("all_policies", [])
                policies_detail = data.get("policies_detail", {})
                for policy_data in policies:
                    policy_arn = policy_data.get("Arn")
                    policy_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn.split(":")[-1]
                    policy_detail = policies_detail.get(policy_name, {})
                    policy = self._normalize_policy(policy_data, policy_detail, context)
                    if policy:
                        all_resources.append(policy)
            
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
    
    def _normalize_user(
        self, user_data: Dict[str, Any], user_detail: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an IAM user."""
        username = user_data.get("UserName")
        if not username:
            return None
        
        arn = user_data.get("Arn")
        account_id = context.account_id
        if arn:
            parsed_arn = parse_arn(arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
        
        resource_id = generate_resource_id(
            service="iam",
            resource_type="user",
            resource_identifier=username,
            account_id=account_id,
        )
        
        create_date = normalize_timestamp(user_data.get("CreateDate"))
        password_last_used = normalize_timestamp(user_data.get("PasswordLastUsed"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.IAM_USER,
            Fields.SERVICE: "iam",
            Fields.RESOURCE_TYPE: "user",
            Fields.RESOURCE_ID: username,
            Fields.ARN: arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: "global",  # IAM is global
            Fields.NAME: username,
            Fields.CREATED_AT: create_date,
            Fields.LAST_MODIFIED: password_last_used,
        }
        
        # Add relationships
        relationships = []
        
        # Groups
        groups = user_detail.get("groups", {}).get("groups", [])
        for group in groups:
            group_name = group.get("GroupName")
            if group_name:
                group_resource_id = generate_resource_id(
                    service="iam",
                    resource_type="group",
                    resource_identifier=group_name,
                    account_id=account_id,
                )
                relationships.append({
                    "target_id": group_resource_id,
                    "target_type": ResourceTypes.IAM_GROUP,
                    "relationship_type": RelationshipTypes.MEMBER_OF,
                })
        
        # Attached policies
        attached_policies = user_detail.get("attached_policies", {}).get("attached_policies", [])
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            if policy_arn:
                relationships.append({
                    "target_arn": policy_arn,
                    "target_type": ResourceTypes.IAM_POLICY,
                    "relationship_type": RelationshipTypes.HAS_POLICY,
                })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "user_id": user_data.get("UserId"),
            "path": user_data.get("Path"),
            "has_inline_policies": bool(user_detail.get("inline_policies", {}).get("policy_names", [])),
            "has_access_keys": bool(user_detail.get("access_keys", {}).get("access_keys", [])),
            "has_mfa": bool(user_detail.get("mfa_devices", {}).get("mfa_devices", [])),
            "has_login_profile": bool(user_detail.get("login_profile", {}).get("login_profile")),
        }
        
        return normalized
    
    def _normalize_role(
        self, role_data: Dict[str, Any], role_detail: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an IAM role."""
        role_name = role_data.get("RoleName")
        if not role_name:
            return None
        
        arn = role_data.get("Arn")
        account_id = context.account_id
        if arn:
            parsed_arn = parse_arn(arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
        
        resource_id = generate_resource_id(
            service="iam",
            resource_type="role",
            resource_identifier=role_name,
            account_id=account_id,
        )
        
        create_date = normalize_timestamp(role_data.get("CreateDate"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.IAM_ROLE,
            Fields.SERVICE: "iam",
            Fields.RESOURCE_TYPE: "role",
            Fields.RESOURCE_ID: role_name,
            Fields.ARN: arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: "global",
            Fields.NAME: role_name,
            Fields.CREATED_AT: create_date,
        }
        
        # Add relationships
        relationships = []
        
        # Attached policies
        attached_policies = role_detail.get("attached_policies", {}).get("attached_policies", [])
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            if policy_arn:
                relationships.append({
                    "target_arn": policy_arn,
                    "target_type": ResourceTypes.IAM_POLICY,
                    "relationship_type": RelationshipTypes.HAS_POLICY,
                })
        
        # Trust policy (who can assume this role)
        trust_policy = role_detail.get("trust_policy", {}).get("trust_policy")
        if trust_policy:
            normalized[Fields.METADATA] = {"trust_policy": trust_policy}
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        if Fields.METADATA not in normalized:
            normalized[Fields.METADATA] = {}
        normalized[Fields.METADATA].update({
            "role_id": role_data.get("RoleId"),
            "path": role_data.get("Path"),
            "description": role_data.get("Description"),
            "max_session_duration": role_data.get("MaxSessionDuration"),
            "has_inline_policies": bool(role_detail.get("inline_policies", {}).get("policy_names", [])),
        })
        
        return normalized
    
    def _normalize_group(
        self, group_data: Dict[str, Any], group_detail: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an IAM group."""
        group_name = group_data.get("GroupName")
        if not group_name:
            return None
        
        arn = group_data.get("Arn")
        account_id = context.account_id
        if arn:
            parsed_arn = parse_arn(arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
        
        resource_id = generate_resource_id(
            service="iam",
            resource_type="group",
            resource_identifier=group_name,
            account_id=account_id,
        )
        
        create_date = normalize_timestamp(group_data.get("CreateDate"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.IAM_GROUP,
            Fields.SERVICE: "iam",
            Fields.RESOURCE_TYPE: "group",
            Fields.RESOURCE_ID: group_name,
            Fields.ARN: arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: "global",
            Fields.NAME: group_name,
            Fields.CREATED_AT: create_date,
        }
        
        # Add relationships
        relationships = []
        
        # Attached policies
        attached_policies = group_detail.get("attached_policies", {}).get("attached_policies", [])
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            if policy_arn:
                relationships.append({
                    "target_arn": policy_arn,
                    "target_type": ResourceTypes.IAM_POLICY,
                    "relationship_type": RelationshipTypes.HAS_POLICY,
                })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "group_id": group_data.get("GroupId"),
            "path": group_data.get("Path"),
            "has_inline_policies": bool(group_detail.get("inline_policies", {}).get("policy_names", [])),
        }
        
        return normalized
    
    def _normalize_policy(
        self, policy_data: Dict[str, Any], policy_detail: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an IAM policy."""
        policy_arn = policy_data.get("Arn")
        if not policy_arn:
            return None
        
        # Extract policy name
        policy_name = policy_arn.split("/")[-1] if "/" in policy_arn else policy_arn.split(":")[-1]
        
        parsed_arn = parse_arn(policy_arn)
        account_id = context.account_id
        if parsed_arn:
            account_id = parsed_arn.get("account_id") or account_id
        
        resource_id = generate_resource_id(
            service="iam",
            resource_type="policy",
            resource_identifier=policy_name,
            account_id=account_id,
        )
        
        create_date = normalize_timestamp(policy_data.get("CreateDate"))
        update_date = normalize_timestamp(policy_data.get("UpdateDate"))
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.IAM_POLICY,
            Fields.SERVICE: "iam",
            Fields.RESOURCE_TYPE: "policy",
            Fields.RESOURCE_ID: policy_name,
            Fields.ARN: policy_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: "global",
            Fields.NAME: policy_name,
            Fields.CREATED_AT: create_date,
            Fields.UPDATED_AT: update_date,
        }
        
        # Add metadata
        policy_meta = policy_detail.get("policy", {}).get("policy", {})
        normalized[Fields.METADATA] = {
            "policy_id": policy_data.get("PolicyId"),
            "path": policy_data.get("Path"),
            "default_version_id": policy_meta.get("DefaultVersionId"),
            "attachment_count": policy_data.get("AttachmentCount", 0),
            "is_attachable": policy_data.get("IsAttachable", True),
            "version_count": len(policy_detail.get("policy_versions", {}).get("versions", [])),
        }
        
        return normalized

