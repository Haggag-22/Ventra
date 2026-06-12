"""Registry of all AWS collectors. The runner executes every registered collector."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
from .control_plane.cloudtrail import CloudTrailCollector
from .control_plane.config import ConfigCollector
from .control_plane.log_posture import LogPostureCollector
from .detections.detective import DetectiveCollector
from .detections.guardduty import GuardDutyCollector
from .detections.inspector2 import Inspector2Collector
from .detections.macie import MacieCollector
from .detections.securityhub import SecurityHubCollector
from .identity.account import AccountCollector
from .identity.iam import IamCollector
from .identity.kms import KmsCollector
from .identity.secrets import SecretsCollector
from .network.cloudfront import CloudFrontCollector
from .network.elb_alb import ElbAlbCollector
from .network.route53_resolver import Route53ResolverCollector
from .network.vpc_flow import VpcFlowCollector
from .network.waf import WafCollector
from .workloads.ec2 import Ec2Collector
from .workloads.eks_audit import EksAuditCollector
from .workloads.lambda_ import LambdaCollector
from .workloads.s3 import S3Collector
from .workloads.s3_access import S3AccessCollector

AWS_REGISTRY = CollectorRegistry()

# Registration order — used when running all collectors.
COLLECTOR_ORDER: list[str] = []

for _cls in (
    # baseline
    AccountCollector,
    CloudTrailCollector,
    IamCollector,
    VpcFlowCollector,
    WafCollector,
    GuardDutyCollector,
    MacieCollector,
    DetectiveCollector,
    # extended
    ConfigCollector,
    SecurityHubCollector,
    Inspector2Collector,
    KmsCollector,
    SecretsCollector,
    Ec2Collector,
    S3Collector,
    LambdaCollector,
    # access / data-plane logs
    ElbAlbCollector,
    CloudFrontCollector,
    S3AccessCollector,
    Route53ResolverCollector,
    EksAuditCollector,
    LogPostureCollector,
):
    AWS_REGISTRY.register(_cls)
    COLLECTOR_ORDER.append(_cls.name)


def all_collector_names() -> list[str]:
    """Every registered AWS collector, in stable registration order."""
    return list(COLLECTOR_ORDER)


# conditional services auto-detected when present. Mapping of collector name -> (service, describe-op).
AUTODETECT_COLLECTORS: dict[str, tuple[str, str]] = {
    # Reserved for later phases (cloudfront, transit_gateway, route53_resolver, rds, eks...).
}
