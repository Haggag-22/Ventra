"""
Normalizers package.

Service-specific normalizers for AWS collector data.
"""

from .cloudtrail import CloudTrailNormalizer
from .ec2 import EC2Normalizer
from .iam import IAMNormalizer
from .dynamodb import DynamoDBNormalizer

__all__ = [
    "CloudTrailNormalizer",
    "EC2Normalizer",
    "IAMNormalizer",
    "DynamoDBNormalizer",
]

