"""AWS collector registry — loaded only for AWS acquisition and collection."""

from __future__ import annotations

from collector.lib.base import CollectorRegistry
from collector.engine.api.aws.control_plane.cloudtrail import CloudTrailCollector
from collector.engine.api.aws.control_plane.config import ConfigCollector
from collector.engine.api.aws.control_plane.log_posture import LogPostureCollector
from collector.engine.api.aws.detections.detective import DetectiveCollector
from collector.engine.api.aws.detections.guardduty import GuardDutyCollector
from collector.engine.api.aws.detections.inspector2 import Inspector2Collector
from collector.engine.api.aws.detections.macie import MacieCollector
from collector.engine.api.aws.detections.securityhub import SecurityHubCollector
from collector.engine.api.aws.identity.account import AccountCollector
from collector.engine.api.aws.identity.iam import IamCollector
from collector.engine.api.aws.identity.kms import KmsCollector
from collector.engine.api.aws.identity.secrets import SecretsCollector
from collector.engine.api.aws.network.apigateway import ApigatewayCollector
from collector.engine.api.aws.network.cloudfront import CloudFrontCollector
from collector.engine.api.aws.network.elb_alb import ElbAlbCollector
from collector.engine.api.aws.network.route53_resolver import Route53ResolverCollector
from collector.engine.api.aws.network.vpc_flow import VpcFlowCollector
from collector.engine.api.aws.network.waf import WafCollector
from collector.engine.api.aws.workloads.ec2 import Ec2Collector
from collector.engine.api.aws.workloads.eks_audit import EksAuditCollector
from collector.engine.api.aws.workloads.lambda_logs import LambdaLogsCollector
from collector.engine.api.aws.workloads.lambda_ import LambdaCollector
from collector.engine.api.aws.workloads.rds_logs import RdsLogsCollector
from collector.engine.api.aws.workloads.s3 import S3Collector
from collector.engine.api.aws.workloads.s3_access import S3AccessCollector

_COLLECTOR_CLASSES = (
    AccountCollector,
    CloudTrailCollector,
    IamCollector,
    VpcFlowCollector,
    WafCollector,
    GuardDutyCollector,
    MacieCollector,
    DetectiveCollector,
    ConfigCollector,
    SecurityHubCollector,
    Inspector2Collector,
    KmsCollector,
    SecretsCollector,
    Ec2Collector,
    S3Collector,
    LambdaCollector,
    LambdaLogsCollector,
    ElbAlbCollector,
    ApigatewayCollector,
    CloudFrontCollector,
    S3AccessCollector,
    Route53ResolverCollector,
    EksAuditCollector,
    RdsLogsCollector,
    LogPostureCollector,
)

_registry: CollectorRegistry | None = None
_order: list[str] | None = None


def get() -> tuple[CollectorRegistry, list[str]]:
    global _registry, _order
    if _registry is None:
        _registry = CollectorRegistry()
        _order = []
        for cls in _COLLECTOR_CLASSES:
            _registry.register(cls)
            _order.append(cls.name)
    return _registry, _order
