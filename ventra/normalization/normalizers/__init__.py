"""
Normalizers package.

Service-specific normalizers for AWS collector data.
"""

from .cloudtrail import CloudTrailNormalizer
from .ec2 import EC2Normalizer
from .iam import IAMNormalizer
from .dynamodb import DynamoDBNormalizer
from .s3 import S3Normalizer
from .eks import EKSNormalizer
from .lambda_func import LambdaNormalizer
from .vpc import VPCNormalizer
from .guardduty import GuardDutyNormalizer
from .kms import KMSNormalizer
from .sns import SNSNormalizer
from .sqs import SQSNormalizer
from .eventbridge import EventBridgeNormalizer
from .elb import ELBNormalizer
from .securityhub import SecurityHubNormalizer
from .apigw import APIGWNormalizer
from .cloudwatch import CloudWatchNormalizer
from .route53 import Route53Normalizer

__all__ = [
    "CloudTrailNormalizer",
    "EC2Normalizer",
    "IAMNormalizer",
    "DynamoDBNormalizer",
    "S3Normalizer",
    "EKSNormalizer",
    "LambdaNormalizer",
    "VPCNormalizer",
    "GuardDutyNormalizer",
    "KMSNormalizer",
    "SNSNormalizer",
    "SQSNormalizer",
    "EventBridgeNormalizer",
    "ELBNormalizer",
    "SecurityHubNormalizer",
    "APIGWNormalizer",
    "CloudWatchNormalizer",
    "Route53Normalizer",
]

