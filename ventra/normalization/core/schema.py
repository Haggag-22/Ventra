"""
Core schemas and constants for normalization.

Defines standardized field names and schema templates that all normalizers
should follow to ensure consistent output across all AWS services.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime


# =============================================================================
# STANDARDIZED FIELD NAMES
# =============================================================================

class Fields:
    """Standardized field names used across all normalized records."""
    
    # Core identifiers
    ID = "id"  # Unique identifier for the record
    TYPE = "type"  # Record type (e.g., "aws.s3.bucket", "aws.ec2.instance")
    SERVICE = "service"  # AWS service name (e.g., "s3", "ec2", "iam")
    RESOURCE_TYPE = "resource_type"  # Resource type within service
    
    # AWS identifiers
    ARN = "arn"  # AWS Resource Name
    ACCOUNT_ID = "account_id"  # AWS account ID
    REGION = "region"  # AWS region
    RESOURCE_ID = "resource_id"  # Service-specific resource ID (e.g., instance-id, bucket-name)
    
    # Timestamps (all ISO 8601 UTC)
    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    DELETED_AT = "deleted_at"
    LAST_MODIFIED = "last_modified"
    FIRST_OBSERVED = "first_observed"
    LAST_OBSERVED = "last_observed"
    COLLECTED_AT = "collected_at"  # When Ventra collected this data
    
    # Event-specific fields
    EVENT_ID = "event_id"
    EVENT_TIME = "event_time"
    EVENT_NAME = "event_name"
    EVENT_SOURCE = "event_source"
    EVENT_TYPE = "event_type"
    USER_IDENTITY = "user_identity"
    SOURCE_IP = "source_ip"
    USER_AGENT = "user_agent"
    REQUEST_ID = "request_id"
    ERROR_CODE = "error_code"
    ERROR_MESSAGE = "error_message"
    
    # Resource metadata
    NAME = "name"
    TAGS = "tags"  # Dict[str, str]
    STATE = "state"  # Current state (e.g., "running", "stopped", "active")
    STATUS = "status"  # Status (e.g., "available", "in-use")
    
    # Relationships
    RELATIONSHIPS = "relationships"  # List of relationship objects
    
    # Raw data preservation
    RAW = "raw"  # Original raw data from collector (optional, for reference)
    METADATA = "metadata"  # Additional metadata dict


# =============================================================================
# SCHEMA TEMPLATES
# =============================================================================

def event_schema_template() -> Dict[str, Any]:
    """
    Template for normalized event records (e.g., CloudTrail, CloudWatch Events).
    
    Returns a dict with required fields and their types/comments.
    """
    return {
        Fields.EVENT_ID: None,  # str: Unique event identifier
        Fields.TYPE: None,  # str: e.g., "aws.cloudtrail.event"
        Fields.SERVICE: None,  # str: e.g., "cloudtrail"
        Fields.EVENT_TIME: None,  # str: ISO 8601 UTC timestamp
        Fields.EVENT_NAME: None,  # str: e.g., "CreateBucket", "RunInstances"
        Fields.EVENT_SOURCE: None,  # str: e.g., "s3.amazonaws.com"
        Fields.ACCOUNT_ID: None,  # str: AWS account ID
        Fields.REGION: None,  # str: AWS region
        Fields.USER_IDENTITY: None,  # dict: User/role identity info
        Fields.SOURCE_IP: None,  # str: Source IP address (optional)
        Fields.USER_AGENT: None,  # str: User agent string (optional)
        Fields.REQUEST_ID: None,  # str: AWS request ID (optional)
        Fields.ERROR_CODE: None,  # str: Error code if failed (optional)
        Fields.ERROR_MESSAGE: None,  # str: Error message if failed (optional)
        Fields.RESOURCE_ID: None,  # str: Affected resource ID (optional)
        Fields.ARN: None,  # str: ARN of affected resource (optional)
        Fields.RAW: None,  # dict: Original raw event data (optional)
    }


def resource_schema_template() -> Dict[str, Any]:
    """
    Template for normalized resource records (e.g., S3 buckets, EC2 instances).
    
    Returns a dict with required fields and their types/comments.
    """
    return {
        Fields.ID: None,  # str: Unique resource identifier
        Fields.TYPE: None,  # str: e.g., "aws.s3.bucket", "aws.ec2.instance"
        Fields.SERVICE: None,  # str: e.g., "s3", "ec2"
        Fields.RESOURCE_TYPE: None,  # str: e.g., "bucket", "instance"
        Fields.RESOURCE_ID: None,  # str: Service-specific ID (e.g., bucket name, instance-id)
        Fields.ARN: None,  # str: AWS Resource Name (if available)
        Fields.ACCOUNT_ID: None,  # str: AWS account ID
        Fields.REGION: None,  # str: AWS region
        Fields.NAME: None,  # str: Resource name (optional)
        Fields.STATE: None,  # str: Current state (optional)
        Fields.STATUS: None,  # str: Current status (optional)
        Fields.CREATED_AT: None,  # str: ISO 8601 UTC timestamp (optional)
        Fields.UPDATED_AT: None,  # str: ISO 8601 UTC timestamp (optional)
        Fields.LAST_MODIFIED: None,  # str: ISO 8601 UTC timestamp (optional)
        Fields.TAGS: None,  # dict[str, str]: Resource tags (optional)
        Fields.RELATIONSHIPS: None,  # list: Related resources (optional)
        Fields.COLLECTED_AT: None,  # str: ISO 8601 UTC timestamp when collected
        Fields.RAW: None,  # dict: Original raw resource data (optional)
        Fields.METADATA: None,  # dict: Additional metadata (optional)
    }


def relationship_schema_template() -> Dict[str, Any]:
    """
    Template for relationship records linking resources together.
    
    Returns a dict with required fields and their types/comments.
    """
    return {
        "source_id": None,  # str: ID of source resource
        "source_type": None,  # str: Type of source resource
        "source_arn": None,  # str: ARN of source resource (optional)
        "target_id": None,  # str: ID of target resource
        "target_type": None,  # str: Type of target resource
        "target_arn": None,  # str: ARN of target resource (optional)
        "relationship_type": None,  # str: e.g., "attached_to", "contains", "uses", "created_by"
        "metadata": None,  # dict: Additional relationship metadata (optional)
    }


# =============================================================================
# TYPE CONSTANTS
# =============================================================================

class ResourceTypes:
    """Standard resource type identifiers."""
    
    # S3
    S3_BUCKET = "aws.s3.bucket"
    S3_OBJECT = "aws.s3.object"
    S3_VERSION = "aws.s3.version"
    
    # EC2
    EC2_INSTANCE = "aws.ec2.instance"
    EC2_VOLUME = "aws.ec2.volume"
    EC2_SNAPSHOT = "aws.ec2.snapshot"
    EC2_SECURITY_GROUP = "aws.ec2.security_group"
    EC2_NETWORK_INTERFACE = "aws.ec2.network_interface"
    
    # IAM
    IAM_USER = "aws.iam.user"
    IAM_ROLE = "aws.iam.role"
    IAM_GROUP = "aws.iam.group"
    IAM_POLICY = "aws.iam.policy"
    
    # CloudTrail
    CLOUDTRAIL_EVENT = "aws.cloudtrail.event"
    
    # Security Hub
    SECURITYHUB_FINDING = "aws.securityhub.finding"
    
    # DynamoDB
    DYNAMODB_TABLE = "aws.dynamodb.table"
    DYNAMODB_BACKUP = "aws.dynamodb.backup"
    
    # Lambda
    LAMBDA_FUNCTION = "aws.lambda.function"
    
    # EKS
    EKS_CLUSTER = "aws.eks.cluster"
    EKS_NODEGROUP = "aws.eks.nodegroup"
    
    # VPC
    VPC = "aws.vpc.vpc"
    VPC_SUBNET = "aws.vpc.subnet"
    VPC_SECURITY_GROUP = "aws.vpc.security_group"
    
    # Generic
    UNKNOWN = "aws.unknown"


class RelationshipTypes:
    """Standard relationship type identifiers."""
    
    ATTACHED_TO = "attached_to"
    CONTAINS = "contains"
    USES = "uses"
    CREATED_BY = "created_by"
    ASSUMES = "assumes"
    MEMBER_OF = "member_of"
    HAS_POLICY = "has_policy"
    REFERENCES = "references"
    DEPENDS_ON = "depends_on"

